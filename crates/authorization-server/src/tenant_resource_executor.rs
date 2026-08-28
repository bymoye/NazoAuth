//! PostgreSQL-backed executor for the tenant-resource protocol.
//!
//! The ControlOperation admission path owns the wire and signature boundary.
//! This module owns the database transaction and keeps that boundary separate:
//! expensive preparation (password hashing, registration policy, and
//! certificate validation) happens before the mutation transaction, while
//! resource rows, revision state, the audit chain, and the typed operation
//! outcome are committed as one unit.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use diesel::{OptionalExtension as _, QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl as _};
use futures_util::future::BoxFuture;
use nazo_auth::{CreateClientRequest, OAuthClient};
use nazo_identity::ports::RepositoryError;
use nazo_identity::{TenantContext, TenantId};
use nazo_key_management::validate_mtls_trust_anchor;
use nazo_operator_protocol::{
    ControlResultData, Openid4vcTrustPolicy, ProtocolError, TenantResourceIdentity,
    TenantResourceKind, TenantResourceMapping, TenantResourceSelector,
    canonical_tenant_resource_manifest_sha256, validate_control_result_data_for_wire,
    validate_openid4vc_trust_policy,
};
use nazo_postgres::{
    NewStoredOpenid4vcTrustPolicy, NewTenantResourceBinding, Openid4vcTrustPolicyClientBind,
    Openid4vcTrustPolicyForClient, Openid4vcTrustPolicyRevoke, Openid4vcTrustPolicyWrite,
    OperatorManagedTrustAnchor, TenantResourceBinding, TenantResourceBindingDeactivate,
    TenantResourceRepository, TenantResourceStateCas, UserInsert,
    active_public_client_id_on_connection, append_fresh_security_audit_on_connection,
    deactivate_client_on_connection, delete_operator_managed_dataset_on_connection,
    disable_user_on_connection, insert_client_on_connection,
    insert_operator_managed_trust_anchor_on_connection, insert_user_on_connection,
    protect_dataset_claims, revoke_operator_managed_trust_anchor_on_connection,
    upsert_operator_managed_dataset_on_connection,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const APPLY_MANIFEST_SCHEMA: u32 = 1;
const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESOURCE_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_RESOURCE_PAYLOAD_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const MAX_USERNAME_BYTES: usize = 150;
const MAX_EMAIL_BYTES: usize = 254;
const MAX_PASSWORD_BYTES: usize = 512;
const MAX_CLIENT_SECRET_BYTES: usize = 512;
const MAX_CONFIGURATION_ID_BYTES: usize = 255;
const MAX_PROFILE_BYTES: usize = 128 * 1024;
const MAX_CERTIFICATE_BYTES: usize = 256 * 1024;
const MAX_DATASET_CLAIMS_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TenantResourceAction {
    Apply,
    Enumerate,
    Revoke,
}

/// Typed, already validated resource payload handed to the persistence layer.
#[derive(Clone)]
pub enum TenantResourcePayload {
    User(UserResourcePayload),
    OauthClient(Box<OauthClientResourcePayload>),
    MtlsTrustAnchor(MtlsTrustAnchorResourcePayload),
    Openid4vcDataset(Openid4vcDatasetResourcePayload),
    Openid4vcTrustPolicy(Box<Openid4vcTrustPolicyResourcePayload>),
}

#[derive(Clone)]
pub struct UserResourcePayload {
    pub username: String,
    pub email: String,
    pub password: String,
    pub email_verified: bool,
    pub profile: Option<Value>,
}

#[derive(Clone)]
pub struct OauthClientResourcePayload {
    pub request: CreateClientRequest,
    pub supplied_secret: Option<String>,
    pub trust_policy_resource_id: Option<String>,
}

#[derive(Clone)]
pub struct MtlsTrustAnchorResourcePayload {
    pub client_resource_id: String,
    pub certificate_pem: String,
}

#[derive(Clone)]
pub struct Openid4vcDatasetResourcePayload {
    pub user_resource_id: String,
    pub configuration_id: String,
    pub claims: Value,
}

#[derive(Clone)]
pub struct Openid4vcTrustPolicyResourcePayload {
    pub public_material: Openid4vcTrustPolicy,
}

#[derive(Clone)]
pub struct PreparedTenantResource {
    pub identity: TenantResourceIdentity,
    /// Apply carries one payload; Revoke and Enumerate do not.
    pub payload: Option<TenantResourcePayload>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TenantResourceExecutorError {
    Conflict,
    Unavailable,
    Rejected,
    InvalidPayload(&'static str),
    TooLarge,
}

impl fmt::Display for TenantResourceExecutorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Conflict => "tenant-resource consistency conflict",
            Self::Unavailable => "tenant-resource persistence unavailable",
            Self::Rejected => "tenant-resource operation rejected",
            Self::InvalidPayload(message) => message,
            Self::TooLarge => "tenant-resource payload too large",
        })
    }
}

impl std::error::Error for TenantResourceExecutorError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyManifest {
    schema: u32,
    resources: Vec<ManifestResource>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestResource {
    kind: TenantResourceKind,
    resource_id: String,
    payload_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserManifestPayload {
    username: String,
    email: String,
    password: String,
    email_verified: bool,
    #[serde(default)]
    profile: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OauthClientManifestPayload {
    request: CreateClientRequest,
    #[serde(default)]
    supplied_secret: Option<String>,
    #[serde(default)]
    trust_policy_resource_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MtlsTrustAnchorManifestPayload {
    client_resource_id: String,
    certificate_pem: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Openid4vcDatasetManifestPayload {
    user_resource_id: String,
    configuration_id: String,
    claims: Value,
}

/// Change-set decoder for the current ControlOperation pipeline.
/// `raw_manifest` carries the decoded Apply-manifest JSON.
/// Every manifest resource must be pre-authorized by the signed identity set
/// (`authorized`), and each per-resource payload must hash exactly to its
/// signed digest — the same material binding as the external public JWK.
pub(crate) fn decode_change_set_payloads(
    raw_manifest: &[u8],
    authorized: &BTreeMap<(TenantResourceKind, String), TenantResourceIdentity>,
) -> Result<Vec<PreparedTenantResource>, TenantResourceExecutorError> {
    if raw_manifest.is_empty() {
        return Err(TenantResourceExecutorError::InvalidPayload(
            "manifest is empty",
        ));
    }
    if raw_manifest.len() > MAX_MANIFEST_BYTES {
        return Err(TenantResourceExecutorError::TooLarge);
    }
    let manifest: ApplyManifest = serde_json::from_slice(raw_manifest)
        .map_err(|_| TenantResourceExecutorError::InvalidPayload("invalid resource manifest"))?;
    if manifest.schema != APPLY_MANIFEST_SCHEMA
        || manifest.resources.is_empty()
        || manifest.resources.len() > nazo_operator_protocol::MAX_TENANT_RESOURCE_IDENTITIES
    {
        return Err(TenantResourceExecutorError::InvalidPayload(
            "unsupported resource manifest",
        ));
    }
    let mut seen_identities = BTreeSet::new();
    let mut payload_total = 0usize;
    let mut prepared = Vec::with_capacity(manifest.resources.len());
    for resource in manifest.resources {
        validate_resource_id(&resource.resource_id)?;
        if !seen_identities.insert((resource.kind, resource.resource_id.clone())) {
            return Err(TenantResourceExecutorError::InvalidPayload(
                "resource identities must be unique",
            ));
        }
        let payload = URL_SAFE_NO_PAD
            .decode(&resource.payload_base64url)
            .map_err(|_| {
                TenantResourceExecutorError::InvalidPayload(
                    "resource payload is not valid base64url",
                )
            })?;
        if payload.is_empty() || payload.len() > MAX_RESOURCE_PAYLOAD_BYTES {
            return Err(if payload.len() > MAX_RESOURCE_PAYLOAD_BYTES {
                TenantResourceExecutorError::TooLarge
            } else {
                TenantResourceExecutorError::InvalidPayload("resource payload is empty")
            });
        }
        payload_total = payload_total
            .checked_add(payload.len())
            .ok_or(TenantResourceExecutorError::TooLarge)?;
        if payload_total > MAX_RESOURCE_PAYLOAD_TOTAL_BYTES {
            return Err(TenantResourceExecutorError::TooLarge);
        }
        let identity = authorized
            .get(&(resource.kind, resource.resource_id.clone()))
            .ok_or(TenantResourceExecutorError::InvalidPayload(
                "manifest resource is not authorized by task",
            ))?;
        if sha256_hex(&payload) != identity.digest {
            return Err(TenantResourceExecutorError::InvalidPayload(
                "resource payload digest does not match task",
            ));
        }
        let typed = decode_payload(resource.kind, &payload)?;
        prepared.push(PreparedTenantResource {
            identity: identity.clone(),
            payload: Some(typed),
        });
    }
    if prepared.len() != authorized.len() {
        return Err(TenantResourceExecutorError::InvalidPayload(
            "manifest resources do not match task",
        ));
    }
    Ok(prepared)
}

fn decode_payload(
    kind: TenantResourceKind,
    payload: &[u8],
) -> Result<TenantResourcePayload, TenantResourceExecutorError> {
    match kind {
        TenantResourceKind::User => {
            let value: UserManifestPayload = serde_json::from_slice(payload)
                .map_err(|_| TenantResourceExecutorError::InvalidPayload("invalid user payload"))?;
            validate_text(&value.username, MAX_USERNAME_BYTES)?;
            validate_text(&value.email, MAX_EMAIL_BYTES)?;
            validate_text(&value.password, MAX_PASSWORD_BYTES)?;
            if let Some(profile) = &value.profile {
                let size = serde_json::to_vec(profile)
                    .map_err(|_| {
                        TenantResourceExecutorError::InvalidPayload("invalid user profile")
                    })?
                    .len();
                if size > MAX_PROFILE_BYTES {
                    return Err(TenantResourceExecutorError::TooLarge);
                }
            }
            Ok(TenantResourcePayload::User(UserResourcePayload {
                username: value.username,
                email: value.email,
                password: value.password,
                email_verified: value.email_verified,
                profile: value.profile,
            }))
        }
        TenantResourceKind::OauthClient => {
            let value: OauthClientManifestPayload =
                serde_json::from_slice(payload).map_err(|_| {
                    TenantResourceExecutorError::InvalidPayload("invalid oauth client payload")
                })?;
            if let Some(secret) = &value.supplied_secret {
                validate_text(secret, MAX_CLIENT_SECRET_BYTES)?;
            }
            Ok(TenantResourcePayload::OauthClient(Box::new(
                OauthClientResourcePayload {
                    request: value.request,
                    supplied_secret: value.supplied_secret,
                    trust_policy_resource_id: value
                        .trust_policy_resource_id
                        .map(|resource_id| validate_resource_id(&resource_id).map(|()| resource_id))
                        .transpose()?,
                },
            )))
        }
        TenantResourceKind::MtlsTrustAnchor => {
            let value: MtlsTrustAnchorManifestPayload =
                serde_json::from_slice(payload).map_err(|_| {
                    TenantResourceExecutorError::InvalidPayload("invalid mTLS trust anchor payload")
                })?;
            validate_resource_id(&value.client_resource_id)?;
            if value.certificate_pem.len() > MAX_CERTIFICATE_BYTES
                || !value
                    .certificate_pem
                    .contains("-----BEGIN CERTIFICATE-----")
                || !value.certificate_pem.contains("-----END CERTIFICATE-----")
            {
                return Err(TenantResourceExecutorError::InvalidPayload(
                    "invalid mTLS trust anchor certificate",
                ));
            }
            Ok(TenantResourcePayload::MtlsTrustAnchor(
                MtlsTrustAnchorResourcePayload {
                    client_resource_id: value.client_resource_id,
                    certificate_pem: value.certificate_pem,
                },
            ))
        }
        TenantResourceKind::Openid4vcDataset => {
            let value: Openid4vcDatasetManifestPayload =
                serde_json::from_slice(payload).map_err(|_| {
                    TenantResourceExecutorError::InvalidPayload("invalid OpenID4VC dataset payload")
                })?;
            validate_resource_id(&value.user_resource_id)?;
            validate_text(&value.configuration_id, MAX_CONFIGURATION_ID_BYTES)?;
            if !value.claims.is_object() {
                return Err(TenantResourceExecutorError::InvalidPayload(
                    "OpenID4VC dataset claims must be an object",
                ));
            }
            let size = serde_json::to_vec(&value.claims)
                .map_err(|_| TenantResourceExecutorError::InvalidPayload("invalid dataset claims"))?
                .len();
            if size > MAX_DATASET_CLAIMS_BYTES {
                return Err(TenantResourceExecutorError::TooLarge);
            }
            Ok(TenantResourcePayload::Openid4vcDataset(
                Openid4vcDatasetResourcePayload {
                    user_resource_id: value.user_resource_id,
                    configuration_id: value.configuration_id,
                    claims: value.claims,
                },
            ))
        }
        TenantResourceKind::Openid4vcTrustPolicy => {
            let public_material: Openid4vcTrustPolicy =
                serde_json::from_slice(payload).map_err(|_| {
                    TenantResourceExecutorError::InvalidPayload(
                        "invalid OpenID4VC trust policy payload",
                    )
                })?;
            validate_openid4vc_trust_policy(&public_material).map_err(|_| {
                TenantResourceExecutorError::InvalidPayload("invalid OpenID4VC trust policy")
            })?;
            Ok(TenantResourcePayload::Openid4vcTrustPolicy(Box::new(
                Openid4vcTrustPolicyResourcePayload { public_material },
            )))
        }
    }
}

fn validate_resource_id(value: &str) -> Result<(), TenantResourceExecutorError> {
    nazo_operator_protocol::validate_file_identifier_value(value)
        .map_err(|_| TenantResourceExecutorError::InvalidPayload("invalid resource identifier"))
}

fn validate_text(value: &str, max_bytes: usize) -> Result<(), TenantResourceExecutorError> {
    if value.trim().is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(TenantResourceExecutorError::InvalidPayload(
            "invalid resource text",
        ));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The result of registration-policy preparation.  The adapter constructing
/// this value is responsible for using the deployment's existing client
/// policy and secret hashing implementation; the executor never invents a
/// parallel policy.
pub struct PreparedOAuthClient {
    pub client: OAuthClient,
    pub client_secret_hash: Option<String>,
}

impl fmt::Debug for PreparedOAuthClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedOAuthClient")
            .field("client_id", &self.client.client_id)
            .field("client_secret_hash", &"[REDACTED]")
            .finish()
    }
}

/// Preparation failures are intentionally coarse.  In particular, a
/// registration secret, password, or certificate body is never included in
/// an error string that could reach logs or an HTTP response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TenantResourcePreparationError {
    Rejected,
    Unavailable,
}

/// Focused bridge to the existing authorization-server registration services.
/// Implementations normally delegate to `ServerAdminClientService` and the
/// configured password/secret hasher.  Keeping this small trait here avoids
/// bypassing those policy services or duplicating their rules in the
/// persistence executor.
pub trait TenantResourcePreparation: Send + Sync {
    fn hash_user_password<'a>(
        &'a self,
        password: String,
    ) -> BoxFuture<'a, Result<String, TenantResourcePreparationError>>;

    fn prepare_oauth_client<'a>(
        &'a self,
        request: CreateClientRequest,
        supplied_secret: Option<String>,
        tenant: TenantContext,
    ) -> BoxFuture<'a, Result<PreparedOAuthClient, TenantResourcePreparationError>>;
}

/// PostgreSQL tenant-resource executor and authoritative state source.
pub struct PostgresTenantResourceExecutor {
    repository: TenantResourceRepository,
    tenant: TenantContext,
    data_key: Option<[u8; 32]>,
    preparation: Arc<dyn TenantResourcePreparation>,
}

impl PostgresTenantResourceExecutor {
    #[must_use]
    pub fn new(
        repository: TenantResourceRepository,
        tenant: TenantContext,
        data_key: Option<[u8; 32]>,
        preparation: Arc<dyn TenantResourcePreparation>,
    ) -> Self {
        Self {
            repository,
            tenant,
            data_key,
            preparation,
        }
    }

    /// Canonical digest of an empty active identity set.
    #[must_use]
    pub fn empty_manifest_sha256() -> String {
        canonical_tenant_resource_manifest_sha256(&[])
            .expect("the empty tenant-resource identity set is valid")
    }
}

impl PostgresTenantResourceExecutor {
    async fn prepare_apply_payloads(
        &self,
        resources: &[PreparedTenantResource],
    ) -> Result<Vec<PreparedApplyPayload>, TenantResourceExecutorError> {
        let mut prepared = Vec::with_capacity(resources.len());
        for resource in resources {
            let Some(payload) = resource.payload.clone() else {
                return Err(TenantResourceExecutorError::Rejected);
            };
            let payload = match payload {
                TenantResourcePayload::User(value) => {
                    let password_hash = self
                        .preparation
                        .hash_user_password(value.password.clone())
                        .await
                        .map_err(map_preparation_error)?;
                    PreparedApplyPayload::User(Box::new(PreparedUser {
                        identity: resource.identity.clone(),
                        password_hash,
                        profile: profile_fields(value.profile.as_ref())
                            .map_err(|_| TenantResourceExecutorError::Rejected)?,
                        username: value.username,
                        email: value.email,
                        email_verified: value.email_verified,
                    }))
                }
                TenantResourcePayload::OauthClient(value) => {
                    let prepared = self
                        .preparation
                        .prepare_oauth_client(value.request, value.supplied_secret, self.tenant)
                        .await
                        .map_err(map_preparation_error)?;
                    PreparedApplyPayload::OauthClient(Box::new(PreparedClient {
                        identity: resource.identity.clone(),
                        trust_policy_resource_id: value.trust_policy_resource_id,
                        prepared,
                    }))
                }
                TenantResourcePayload::MtlsTrustAnchor(value) => {
                    let parsed = validate_mtls_trust_anchor(&value.certificate_pem)
                        .map_err(|_| TenantResourceExecutorError::Rejected)?;
                    PreparedApplyPayload::Mtls(Box::new(PreparedMtls {
                        identity: resource.identity.clone(),
                        client_resource_id: value.client_resource_id,
                        certificate_pem: parsed.certificate_pem,
                        certificate_sha256: parsed.certificate_sha256,
                        subject_dn: parsed.subject_dn,
                        not_before: parsed.not_before,
                        not_after: parsed.not_after,
                    }))
                }
                TenantResourcePayload::Openid4vcDataset(value) => {
                    PreparedApplyPayload::Dataset(Box::new(PreparedDataset {
                        identity: resource.identity.clone(),
                        user_resource_id: value.user_resource_id,
                        configuration_id: value.configuration_id,
                        claims: value.claims,
                    }))
                }
                TenantResourcePayload::Openid4vcTrustPolicy(value) => {
                    validate_openid4vc_trust_policy(&value.public_material)
                        .map_err(|_| TenantResourceExecutorError::Rejected)?;
                    PreparedApplyPayload::TrustPolicy(Box::new(PreparedTrustPolicy {
                        identity: resource.identity.clone(),
                        public_material: value.public_material,
                    }))
                }
            };
            prepared.push(payload);
        }
        prepared.sort_by(|left, right| payload_sort_key(left).cmp(&payload_sort_key(right)));
        Ok(prepared)
    }

    /// Execute one tenant-resource operation on behalf of an accepted
    /// [`nazo_operator_protocol::ControlOperation`] (H07).
    ///
    /// Authorization is the accepted controller-signed operation. Exact
    /// operation-id/request-hash replay, resource mutation, state CAS, audit,
    /// and the typed outcome commit in one PostgreSQL transaction.
    pub(crate) async fn execute_control_operation(
        &self,
        frame: ControlTenantResourceFrame<'_>,
    ) -> Result<ControlTenantResourceOutcome, TenantResourceExecutorError> {
        let ControlTenantResourceFrame {
            deployment_id,
            jti,
            request_sha256,
            actor,
            operation,
            tenant_id,
            resources,
            selectors,
        } = frame;
        if tenant_id != self.tenant.tenant_id.as_uuid().to_string()
            || !is_lower_sha256(request_sha256)
        {
            return Err(TenantResourceExecutorError::Rejected);
        }
        let operation_id =
            Uuid::parse_str(jti).map_err(|_| TenantResourceExecutorError::Rejected)?;
        if let Some(outcome) = self
            .existing_control_outcome(deployment_id, operation_id, request_sha256, operation)
            .await?
        {
            return Ok(outcome);
        }
        let prepared_payloads = match operation {
            TenantResourceAction::Apply => Some(self.prepare_apply_payloads(&resources).await?),
            _ => None,
        };
        let mut connection = self
            .repository
            .connection()
            .await
            .map_err(map_repository_error)?;
        let tenant_uuid = self.tenant.tenant_id.as_uuid();
        let configured_tenant = self.tenant;
        let data_key = self.data_key;
        let deployment_id = deployment_id.to_owned();
        let actor = actor.clone();
        let selectors = selectors.to_vec();

        connection
            .transaction::<ControlTenantResourceOutcome, ExecutorTransactionError, _>(
                async move |connection| {
                    // Serialize replay/conflict decisions and the resource
                    // transaction for one accepted operation identity.
                    TenantResourceRepository::lock_operation_identity_on_connection(
                        connection,
                        &deployment_id,
                        tenant_uuid,
                        jti,
                    )
                    .await
                    .map_err(ExecutorTransactionError::Repository)?;
                    if let Some(outcome) = control_outcome_on_connection(
                        connection,
                        operation_id,
                        request_sha256,
                        tenant_uuid,
                        operation,
                    )
                    .await?
                    {
                        return Ok(outcome);
                    }
                    let current =
                        TenantResourceRepository::state_on_connection(connection, tenant_uuid)
                            .await
                            .map_err(ExecutorTransactionError::Repository)?;
                    let (current_revision, current_manifest) = match current {
                        Some(state) => (state.revision, state.resource_manifest_sha256),
                        None => (0, Self::empty_manifest_sha256()),
                    };

                    let frame = match operation {
                        TenantResourceAction::Apply => ResourceFrame::Apply {
                            resources: &resources,
                            payloads: prepared_payloads.as_deref().ok_or(
                                ExecutorTransactionError::Executor(
                                    TenantResourceExecutorError::Rejected,
                                ),
                            )?,
                        },
                        TenantResourceAction::Revoke => ResourceFrame::Revoke {
                            resources: &resources,
                        },
                        TenantResourceAction::Enumerate => ResourceFrame::Enumerate {
                            selectors: &selectors,
                        },
                    };
                    let frame = run_resource_frame(
                        connection,
                        tenant_uuid,
                        configured_tenant,
                        &data_key,
                        frame,
                    )
                    .await?;

                    if operation == TenantResourceAction::Enumerate {
                        if frame.manifest_sha256 != current_manifest {
                            return Err(ExecutorTransactionError::Executor(
                                TenantResourceExecutorError::Conflict,
                            ));
                        }
                        let audit_event = tenant_resource_audit_event(
                            &deployment_id,
                            &tenant_uuid.to_string(),
                            jti,
                            request_sha256,
                            &actor,
                            operation,
                            current_revision,
                            &frame.manifest_sha256,
                            &frame.resources,
                        );
                        append_fresh_security_audit_on_connection(connection, &audit_event)
                            .await
                            .map_err(ExecutorTransactionError::Diesel)?;
                        let outcome = ControlTenantResourceOutcome {
                            revision: current_revision,
                            resources: frame.resources,
                            resource_mappings: frame.resource_mappings,
                            resource_manifest_sha256: frame.manifest_sha256,
                        };
                        validate_wire_outcome(operation, &outcome)?;
                        record_control_outcome_on_connection(
                            connection,
                            operation_id,
                            request_sha256,
                            tenant_uuid,
                            operation,
                            &outcome,
                        )
                        .await?;
                        return Ok(outcome);
                    }

                    let next_revision = current_revision.checked_add(1).ok_or(
                        ExecutorTransactionError::Executor(
                            TenantResourceExecutorError::Unavailable,
                        ),
                    )?;
                    match TenantResourceRepository::compare_and_set_state_on_connection(
                        connection,
                        tenant_uuid,
                        current_revision,
                        next_revision,
                        &frame.manifest_sha256,
                    )
                    .await
                    .map_err(ExecutorTransactionError::Repository)?
                    {
                        TenantResourceStateCas::Applied(_) => {}
                        TenantResourceStateCas::Conflict(_) => {
                            return Err(transaction_conflict("state_cas"));
                        }
                    }
                    let audit_event = tenant_resource_audit_event(
                        &deployment_id,
                        &tenant_uuid.to_string(),
                        jti,
                        request_sha256,
                        &actor,
                        operation,
                        current_revision,
                        &frame.manifest_sha256,
                        &frame.resources,
                    );
                    append_fresh_security_audit_on_connection(connection, &audit_event)
                        .await
                        .map_err(ExecutorTransactionError::Diesel)?;
                    let outcome = ControlTenantResourceOutcome {
                        revision: next_revision,
                        resources: frame.resources,
                        resource_mappings: frame.resource_mappings,
                        resource_manifest_sha256: frame.manifest_sha256,
                    };
                    validate_wire_outcome(operation, &outcome)?;
                    record_control_outcome_on_connection(
                        connection,
                        operation_id,
                        request_sha256,
                        tenant_uuid,
                        operation,
                        &outcome,
                    )
                    .await?;
                    Ok(outcome)
                },
            )
            .await
            .map_err(map_transaction_error)
    }

    async fn existing_control_outcome(
        &self,
        deployment_id: &str,
        operation_id: Uuid,
        request_hash: &str,
        operation: TenantResourceAction,
    ) -> Result<Option<ControlTenantResourceOutcome>, TenantResourceExecutorError> {
        let mut connection = self
            .repository
            .connection()
            .await
            .map_err(map_repository_error)?;
        let tenant_id = self.tenant.tenant_id.as_uuid();
        connection
            .transaction::<Option<ControlTenantResourceOutcome>, ExecutorTransactionError, _>(
                async move |connection| {
                    let operation_id_text = operation_id.to_string();
                    TenantResourceRepository::lock_operation_identity_on_connection(
                        connection,
                        deployment_id,
                        tenant_id,
                        &operation_id_text,
                    )
                    .await
                    .map_err(ExecutorTransactionError::Repository)?;
                    control_outcome_on_connection(
                        connection,
                        operation_id,
                        request_hash,
                        tenant_id,
                        operation,
                    )
                    .await
                },
            )
            .await
            .map_err(map_transaction_error)
    }
}

/// Prepared values are deliberately not `Debug`: password hashes, encrypted
/// claim ciphertext, and registration material should not accidentally enter
/// a trace or panic message.
enum PreparedApplyPayload {
    User(Box<PreparedUser>),
    OauthClient(Box<PreparedClient>),
    Mtls(Box<PreparedMtls>),
    Dataset(Box<PreparedDataset>),
    TrustPolicy(Box<PreparedTrustPolicy>),
}

struct PreparedUser {
    identity: TenantResourceIdentity,
    password_hash: String,
    profile: ProfileFields,
    username: String,
    email: String,
    email_verified: bool,
}

struct PreparedClient {
    identity: TenantResourceIdentity,
    trust_policy_resource_id: Option<String>,
    prepared: PreparedOAuthClient,
}

struct PreparedMtls {
    identity: TenantResourceIdentity,
    client_resource_id: String,
    certificate_pem: String,
    certificate_sha256: String,
    subject_dn: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

struct PreparedDataset {
    identity: TenantResourceIdentity,
    user_resource_id: String,
    configuration_id: String,
    claims: Value,
}

struct PreparedTrustPolicy {
    identity: TenantResourceIdentity,
    public_material: nazo_operator_protocol::Openid4vcTrustPolicy,
}

fn payload_sort_key(payload: &PreparedApplyPayload) -> (u8, &str) {
    match payload {
        PreparedApplyPayload::User(value) => (0, &value.identity.resource_id),
        PreparedApplyPayload::OauthClient(value) => (1, &value.identity.resource_id),
        PreparedApplyPayload::Mtls(value) => (2, &value.identity.resource_id),
        PreparedApplyPayload::Dataset(value) => (3, &value.identity.resource_id),
        PreparedApplyPayload::TrustPolicy(value) => (4, &value.identity.resource_id),
    }
}

/// Authoritative outcome of one control-operation tenant-resource frame (H07).
/// This is the entire data surface handed back to the ControlResult channel;
/// richer executor internals have no wire representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ControlTenantResourceOutcome {
    /// CAS revision this read/mutation is consistent with.
    pub revision: u64,
    /// Sorted identity set selected by the operation.
    pub resources: Vec<TenantResourceIdentity>,
    /// Apply-only public identifiers assigned by authoritative services.
    pub resource_mappings: Vec<TenantResourceMapping>,
    /// Digest of the complete active tenant-resource identity set.
    pub resource_manifest_sha256: String,
}

impl ControlTenantResourceOutcome {
    pub(crate) fn control_result_data(&self, operation: TenantResourceAction) -> ControlResultData {
        match operation {
            TenantResourceAction::Apply => ControlResultData::TenantResourceApply {
                revision: self.revision,
                resources: self.resources.clone(),
                resource_mappings: self.resource_mappings.clone(),
                resource_manifest_sha256: self.resource_manifest_sha256.clone(),
            },
            TenantResourceAction::Enumerate => ControlResultData::TenantResourceEnumerate {
                revision: self.revision,
                resources: self.resources.clone(),
                resource_manifest_sha256: self.resource_manifest_sha256.clone(),
            },
            TenantResourceAction::Revoke => ControlResultData::TenantResourceRevoke {
                revision: self.revision,
                resources: self.resources.clone(),
                resource_manifest_sha256: self.resource_manifest_sha256.clone(),
            },
        }
    }
}

fn validate_wire_outcome(
    operation: TenantResourceAction,
    outcome: &ControlTenantResourceOutcome,
) -> Result<(), ExecutorTransactionError> {
    validate_control_result_data_for_wire(&outcome.control_result_data(operation)).map_err(
        |error| {
            ExecutorTransactionError::Executor(match error {
                ProtocolError::TooLarge => TenantResourceExecutorError::TooLarge,
                _ => TenantResourceExecutorError::Rejected,
            })
        },
    )
}

#[derive(QueryableByName)]
struct ControlOutcomeRow {
    #[diesel(sql_type = sql_types::Text)]
    request_hash: String,
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    operation: String,
    #[diesel(sql_type = sql_types::Jsonb)]
    outcome: Value,
}

async fn control_outcome_on_connection(
    connection: &mut AsyncPgConnection,
    operation_id: Uuid,
    request_hash: &str,
    tenant_id: Uuid,
    operation: TenantResourceAction,
) -> Result<Option<ControlTenantResourceOutcome>, ExecutorTransactionError> {
    let row = sql_query(
        "SELECT request_hash, tenant_id, operation, outcome
         FROM tenant_resource_control_operations
         WHERE operation_id = $1",
    )
    .bind::<sql_types::Uuid, _>(operation_id)
    .get_result::<ControlOutcomeRow>(connection)
    .await
    .optional()
    .map_err(ExecutorTransactionError::Diesel)?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.request_hash != request_hash
        || row.tenant_id != tenant_id
        || row.operation != operation_name(operation)
    {
        return Err(transaction_conflict("control_operation_replay"));
    }
    let outcome = serde_json::from_value(row.outcome).map_err(|_| {
        ExecutorTransactionError::Executor(TenantResourceExecutorError::Unavailable)
    })?;
    validate_wire_outcome(operation, &outcome)?;
    Ok(Some(outcome))
}

async fn record_control_outcome_on_connection(
    connection: &mut AsyncPgConnection,
    operation_id: Uuid,
    request_hash: &str,
    tenant_id: Uuid,
    operation: TenantResourceAction,
    outcome: &ControlTenantResourceOutcome,
) -> Result<(), ExecutorTransactionError> {
    let outcome = serde_json::to_value(outcome).map_err(|_| {
        ExecutorTransactionError::Executor(TenantResourceExecutorError::Unavailable)
    })?;
    let inserted = sql_query(
        "INSERT INTO tenant_resource_control_operations
             (operation_id, request_hash, tenant_id, operation, outcome)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind::<sql_types::Uuid, _>(operation_id)
    .bind::<sql_types::Text, _>(request_hash)
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Text, _>(operation_name(operation))
    .bind::<sql_types::Jsonb, _>(outcome)
    .execute(connection)
    .await
    .map_err(ExecutorTransactionError::Diesel)?;
    if inserted != 1 {
        return Err(transaction_conflict("control_operation_record"));
    }
    Ok(())
}

/// One accepted control operation's tenant-resource frame (H07): provenance,
/// scope, and typed inputs in a single closed parameter surface.
pub(crate) struct ControlTenantResourceFrame<'a> {
    /// Signed deployment binding that proved local at admission.
    pub deployment_id: &'a str,
    /// Accepted operation id (`operation_id`, doubles as jti).
    pub jti: &'a str,
    /// Canonical request hash of the accepted operation (audit provenance).
    pub request_sha256: &'a str,
    /// Non-secret controller descriptor recorded on the audit event.
    pub actor: &'a Value,
    pub operation: TenantResourceAction,
    /// Tenant scope claimed by the signed payload; must equal the configured
    /// tenant or the executor rejects the frame outright.
    pub tenant_id: &'a str,
    /// Apply/revoke delta.  Apply entries carry digest-bound typed payloads;
    /// revoke entries are payload-less.
    pub resources: Vec<PreparedTenantResource>,
    /// Enumerate selectors; ignored by the other variants.
    pub selectors: &'a [TenantResourceSelector],
}

/// Typed input of one shared tenant-resource frame.
enum ResourceFrame<'a> {
    Apply {
        resources: &'a [PreparedTenantResource],
        payloads: &'a [PreparedApplyPayload],
    },
    Revoke {
        resources: &'a [PreparedTenantResource],
    },
    Enumerate {
        selectors: &'a [TenantResourceSelector],
    },
}

/// Normalized outcome of one shared mutation/enumeration frame.
struct MutationFrameResult {
    /// Sorted identities this operation reports (delta for apply/revoke,
    /// selection for enumerate).
    resources: Vec<TenantResourceIdentity>,
    /// Apply-only public identifier mappings; empty otherwise.
    resource_mappings: Vec<TenantResourceMapping>,
    /// Canonical SHA-256 of the complete active identity set implied by this
    /// frame, recomputed from the database inside the caller's transaction.
    manifest_sha256: String,
}

/// Dispatch one tenant-resource ControlOperation onto the CAS engine so
/// ownership checks, dependency ordering, identity locks, and manifest
/// recomputation have one owner.
async fn run_resource_frame(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    configured_tenant: TenantContext,
    data_key: &Option<[u8; 32]>,
    frame: ResourceFrame<'_>,
) -> Result<MutationFrameResult, ExecutorTransactionError> {
    match frame {
        ResourceFrame::Apply {
            resources,
            payloads,
        } => {
            let (resources, resource_mappings, manifest_sha256) = apply_resources(
                connection,
                tenant_id,
                configured_tenant,
                resources,
                payloads,
                data_key,
            )
            .await?;
            Ok(MutationFrameResult {
                resources,
                resource_mappings,
                manifest_sha256,
            })
        }
        ResourceFrame::Revoke { resources } => {
            let (resources, manifest_sha256) =
                revoke_resources(connection, tenant_id, configured_tenant, resources).await?;
            Ok(MutationFrameResult {
                resources,
                resource_mappings: Vec::new(),
                manifest_sha256,
            })
        }
        ResourceFrame::Enumerate { selectors } => {
            let (selected, complete) =
                enumerate_resources(connection, tenant_id, selectors).await?;
            let manifest_sha256 =
                canonical_tenant_resource_manifest_sha256(&complete).map_err(|_| {
                    ExecutorTransactionError::Executor(TenantResourceExecutorError::Unavailable)
                })?;
            Ok(MutationFrameResult {
                resources: selected,
                resource_mappings: Vec::new(),
                manifest_sha256,
            })
        }
    }
}

async fn apply_resources(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    tenant: TenantContext,
    resources: &[PreparedTenantResource],
    payloads: &[PreparedApplyPayload],
    data_key: &Option<[u8; 32]>,
) -> Result<
    (
        Vec<TenantResourceIdentity>,
        Vec<TenantResourceMapping>,
        String,
    ),
    ExecutorTransactionError,
> {
    let active = active_binding_map(connection, tenant_id).await?;
    let mut locators = BTreeMap::<ResourceKey, String>::new();
    let delta_keys = resources
        .iter()
        .map(|resource| ResourceKey::from_identity(&resource.identity))
        .collect::<std::collections::BTreeSet<_>>();
    let mut available_keys = active
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    available_keys.extend(delta_keys.iter().cloned());
    validate_desired_dependencies(payloads, &available_keys)?;

    // Every identity lock is acquired in one global order before either the
    // dependency-ordered creation phase or the revision CAS.  This keeps a
    // delta apply from racing a revoke/apply for an existing identity.
    let mut locked_keys = active
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    locked_keys.extend(delta_keys.iter().cloned());
    for key in locked_keys {
        TenantResourceRepository::lock_binding_identity_on_connection(
            connection,
            tenant_id,
            kind_name(key.kind),
            &key.resource_id,
        )
        .await
        .map_err(ExecutorTransactionError::Repository)?;
    }
    // Active bindings are part of the available dependency graph.  Keep
    // their operator-owned locators in the same map as newly-created delta
    // rows so an mTLS anchor or dataset can refer to a parent omitted from
    // this delta.
    for (key, binding) in &active {
        if !is_operator_locator(&binding.locator, key.kind) {
            return Err(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Rejected,
            ));
        }
        locators.insert(key.clone(), binding.locator.clone());
    }

    // Reusing an active identity is idempotent only when its digest matches.
    // A changed payload must be fenced through an explicit Revoke followed by
    // a fresh Apply; this delta path never overwrites it in place.
    for resource in resources {
        let key = ResourceKey::new(resource.identity.kind, &resource.identity.resource_id);
        if active
            .get(&key)
            .is_some_and(|binding| binding.resource_digest != resource.identity.digest)
        {
            return Err(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Conflict,
            ));
        }
    }

    // Logical references are resolved only after users and clients exist.
    for payload in payloads.iter().filter_map(|p| match p {
        PreparedApplyPayload::User(value) => Some(value),
        _ => None,
    }) {
        if locators.contains_key(&ResourceKey::from_identity(&payload.identity)) {
            continue;
        }
        let profile = &payload.profile;
        let id = insert_user_on_connection(
            connection,
            UserInsert {
                tenant,
                username: &payload.username,
                email: &payload.email,
                password_hash: &payload.password_hash,
                email_verified: payload.email_verified,
                display_name: profile.display_name.as_deref(),
                given_name: profile.given_name.as_deref(),
                family_name: profile.family_name.as_deref(),
                middle_name: profile.middle_name.as_deref(),
                nickname: profile.nickname.as_deref(),
                profile_url: profile.profile_url.as_deref(),
                avatar_url: profile.avatar_url.as_deref(),
                website_url: profile.website_url.as_deref(),
                gender: profile.gender.as_deref(),
                birthdate: profile.birthdate.as_deref(),
                zoneinfo: profile.zoneinfo.as_deref(),
                locale: profile.locale.as_deref(),
                address_formatted: profile.address_formatted.as_deref(),
                address_street_address: profile.address_street_address.as_deref(),
                address_locality: profile.address_locality.as_deref(),
                address_region: profile.address_region.as_deref(),
                address_postal_code: profile.address_postal_code.as_deref(),
                address_country: profile.address_country.as_deref(),
                phone_number: profile.phone_number.as_deref(),
                phone_number_verified: profile.phone_number_verified,
            },
        )
        .await
        .map_err(map_diesel_error)?;
        locators.insert(
            ResourceKey::from_identity(&payload.identity),
            user_locator(id),
        );
    }
    for payload in payloads.iter().filter_map(|p| match p {
        PreparedApplyPayload::OauthClient(value) => Some(value),
        _ => None,
    }) {
        if locators.contains_key(&ResourceKey::from_identity(&payload.identity)) {
            continue;
        }
        let client = &payload.prepared.client;
        if client.tenant_id != tenant.tenant_id.as_uuid()
            || client.realm_id != tenant.realm_id.as_uuid()
            || client.organization_id != tenant.organization_id.as_uuid()
        {
            return Err(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Rejected,
            ));
        }
        insert_client_on_connection(
            connection,
            client,
            payload.prepared.client_secret_hash.as_deref(),
            None,
        )
        .await
        .map_err(map_diesel_error)?;
        locators.insert(
            ResourceKey::from_identity(&payload.identity),
            oauth_client_locator(client.id),
        );
    }
    for payload in payloads.iter().filter_map(|p| match p {
        PreparedApplyPayload::Mtls(value) => Some(value),
        _ => None,
    }) {
        if locators.contains_key(&ResourceKey::from_identity(&payload.identity)) {
            continue;
        }
        let client_key =
            ResourceKey::new(TenantResourceKind::OauthClient, &payload.client_resource_id);
        let client_id = parse_uuid_locator(
            locators
                .get(&client_key)
                .ok_or(ExecutorTransactionError::Executor(
                    TenantResourceExecutorError::Rejected,
                ))?,
            TenantResourceKind::OauthClient,
        )?;
        let request_id = insert_operator_managed_trust_anchor_on_connection(
            connection,
            OperatorManagedTrustAnchor {
                tenant_id: tenant.tenant_id,
                client_id,
                certificate_pem: &payload.certificate_pem,
                certificate_sha256: &payload.certificate_sha256,
                subject_dn: &payload.subject_dn,
                not_before: payload.not_before,
                not_after: payload.not_after,
            },
        )
        .await
        .map_err(map_repository_error)?;
        locators.insert(
            ResourceKey::from_identity(&payload.identity),
            mtls_locator(request_id),
        );
    }
    for payload in payloads.iter().filter_map(|p| match p {
        PreparedApplyPayload::Dataset(value) => Some(value),
        _ => None,
    }) {
        if locators.contains_key(&ResourceKey::from_identity(&payload.identity)) {
            continue;
        }
        let user_key = ResourceKey::new(TenantResourceKind::User, &payload.user_resource_id);
        let user_id = parse_uuid_locator(
            locators
                .get(&user_key)
                .ok_or(ExecutorTransactionError::Executor(
                    TenantResourceExecutorError::Rejected,
                ))?,
            TenantResourceKind::User,
        )?;
        let Some(data_key) = data_key.as_ref() else {
            return Err(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Unavailable,
            ));
        };
        let ciphertext = protect_dataset_claims(
            data_key,
            tenant_id,
            user_id,
            &payload.configuration_id,
            &payload.claims,
        )
        .map_err(|_| {
            ExecutorTransactionError::Executor(TenantResourceExecutorError::Unavailable)
        })?;
        let affected = upsert_operator_managed_dataset_on_connection(
            connection,
            tenant_id,
            user_id,
            &payload.configuration_id,
            ciphertext,
            None,
            None,
        )
        .await
        .map_err(map_diesel_error)?;
        if affected != 1 {
            return Err(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Conflict,
            ));
        }
        locators.insert(
            ResourceKey::from_identity(&payload.identity),
            dataset_locator(user_id, &payload.configuration_id),
        );
    }
    for payload in payloads.iter().filter_map(|p| match p {
        PreparedApplyPayload::TrustPolicy(value) => Some(value),
        _ => None,
    }) {
        if locators.contains_key(&ResourceKey::from_identity(&payload.identity)) {
            continue;
        }
        let public_material = serde_json::to_value(&payload.public_material).map_err(|_| {
            ExecutorTransactionError::Executor(TenantResourceExecutorError::Unavailable)
        })?;
        let applied = TenantResourceRepository::apply_openid4vc_trust_policy_on_connection(
            connection,
            NewStoredOpenid4vcTrustPolicy {
                tenant_id,
                resource_id: &payload.identity.resource_id,
                resource_digest: &payload.identity.digest,
                public_material: &public_material,
                wallet_origins: &payload.public_material.wallet_authorization_origins,
            },
        )
        .await
        .map_err(ExecutorTransactionError::Repository)?;
        let policy_id = match applied {
            Openid4vcTrustPolicyWrite::Applied(policy)
            | Openid4vcTrustPolicyWrite::Replayed(policy) => policy.id,
            Openid4vcTrustPolicyWrite::Conflict(_) => {
                return Err(transaction_conflict("trust_policy_apply"));
            }
        };
        locators.insert(
            ResourceKey::from_identity(&payload.identity),
            trust_policy_locator(policy_id),
        );
    }

    // Bind OAuth clients to the policy only after all logical resources have
    // locators.  This preserves the user/client/mTLS/dataset creation order
    // while allowing a client and a new policy to be introduced together.
    for payload in payloads.iter().filter_map(|p| match p {
        PreparedApplyPayload::OauthClient(value) => Some(value),
        _ => None,
    }) {
        let Some(policy_resource_id) = payload.trust_policy_resource_id.as_deref() else {
            continue;
        };
        let policy_key =
            ResourceKey::new(TenantResourceKind::Openid4vcTrustPolicy, policy_resource_id);
        locators
            .get(&policy_key)
            .ok_or(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Rejected,
            ))?;
        let client_locator = locators
            .get(&ResourceKey::from_identity(&payload.identity))
            .ok_or(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Rejected,
            ))?;
        let client_id = parse_uuid_locator(client_locator, TenantResourceKind::OauthClient)?;
        let policy_digest = resources
            .iter()
            .find(|resource| ResourceKey::from_identity(&resource.identity) == policy_key)
            .map(|resource| resource.identity.digest.as_str())
            .or_else(|| {
                active
                    .get(&policy_key)
                    .map(|binding| binding.resource_digest.as_str())
            })
            .ok_or(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Rejected,
            ))?;
        match TenantResourceRepository::bind_openid4vc_trust_policy_client_on_connection(
            connection,
            tenant_id,
            policy_resource_id,
            policy_digest,
            client_id,
        )
        .await
        .map_err(ExecutorTransactionError::Repository)?
        {
            Openid4vcTrustPolicyClientBind::Bound { .. }
            | Openid4vcTrustPolicyClientBind::Replayed { .. } => {}
            Openid4vcTrustPolicyClientBind::Conflict { .. } => {
                return Err(transaction_conflict("trust_policy_client_bind"));
            }
        }
    }

    for resource in resources {
        let key = ResourceKey::from_identity(&resource.identity);
        let locator = locators
            .get(&key)
            .ok_or(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Rejected,
            ))?;
        TenantResourceRepository::upsert_binding_on_connection(
            connection,
            NewTenantResourceBinding {
                tenant_id,
                resource_kind: kind_name(resource.identity.kind),
                resource_id: &resource.identity.resource_id,
                resource_digest: &resource.identity.digest,
                active: true,
                locator,
            },
        )
        .await
        .map_err(map_repository_error)?;
    }
    let result = sort_identities(resources.iter().map(|r| r.identity.clone()).collect());
    let active_after = active_binding_map(connection, tenant_id).await?;
    let active_after = active_after
        .values()
        .filter_map(|binding| {
            parse_kind(&binding.resource_kind).map(|kind| TenantResourceIdentity {
                kind,
                resource_id: binding.resource_id.clone(),
                digest: binding.resource_digest.clone(),
            })
        })
        .collect::<Vec<_>>();
    let digest = canonical_tenant_resource_manifest_sha256(&active_after)
        .map_err(|_| ExecutorTransactionError::Executor(TenantResourceExecutorError::Rejected))?;

    // Prepare the public mapping set for the typed Apply result. The protocol
    // only exposes User UUIDs and OAuth public client IDs; mTLS, dataset, and
    // trust-policy locators intentionally remain internal.
    let resource_mappings =
        collect_apply_resource_mappings(connection, tenant_id, resources, &locators).await?;
    Ok((result, resource_mappings, digest))
}

async fn collect_apply_resource_mappings(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    resources: &[PreparedTenantResource],
    locators: &BTreeMap<ResourceKey, String>,
) -> Result<Vec<TenantResourceMapping>, ExecutorTransactionError> {
    let mut mappings = Vec::new();
    for resource in resources {
        let public_id = match resource.identity.kind {
            TenantResourceKind::User => {
                let locator = locators
                    .get(&ResourceKey::from_identity(&resource.identity))
                    .ok_or(ExecutorTransactionError::Executor(
                        TenantResourceExecutorError::Rejected,
                    ))?;
                parse_uuid_locator(locator, TenantResourceKind::User)?.to_string()
            }
            TenantResourceKind::OauthClient => {
                let locator = locators
                    .get(&ResourceKey::from_identity(&resource.identity))
                    .ok_or(ExecutorTransactionError::Executor(
                        TenantResourceExecutorError::Rejected,
                    ))?;
                let client_id = parse_uuid_locator(locator, TenantResourceKind::OauthClient)?;
                active_public_client_id_on_connection(connection, tenant_id, client_id)
                    .await
                    .map_err(ExecutorTransactionError::Repository)?
                    .ok_or_else(|| transaction_conflict("apply_oauth_client_mapping"))?
            }
            TenantResourceKind::MtlsTrustAnchor
            | TenantResourceKind::Openid4vcDataset
            | TenantResourceKind::Openid4vcTrustPolicy => {
                continue;
            }
        };
        mappings.push(TenantResourceMapping {
            kind: resource.identity.kind,
            resource_id: resource.identity.resource_id.clone(),
            public_id,
        });
    }
    mappings.sort_by(|left, right| {
        (kind_order(left.kind), left.resource_id.as_str())
            .cmp(&(kind_order(right.kind), right.resource_id.as_str()))
    });
    Ok(mappings)
}

fn validate_desired_dependencies(
    payloads: &[PreparedApplyPayload],
    available_keys: &std::collections::BTreeSet<ResourceKey>,
) -> Result<(), ExecutorTransactionError> {
    for payload in payloads {
        let dependencies = match payload {
            PreparedApplyPayload::OauthClient(value) => value
                .trust_policy_resource_id
                .as_ref()
                .map(|resource_id| {
                    ResourceKey::new(TenantResourceKind::Openid4vcTrustPolicy, resource_id)
                })
                .into_iter()
                .collect::<Vec<_>>(),
            PreparedApplyPayload::Mtls(value) => vec![ResourceKey::new(
                TenantResourceKind::OauthClient,
                &value.client_resource_id,
            )],
            PreparedApplyPayload::Dataset(value) => vec![ResourceKey::new(
                TenantResourceKind::User,
                &value.user_resource_id,
            )],
            PreparedApplyPayload::TrustPolicy(_) | PreparedApplyPayload::User(_) => Vec::new(),
        };
        if dependencies
            .iter()
            .any(|dependency| !available_keys.contains(dependency))
        {
            return Err(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Rejected,
            ));
        }
    }
    Ok(())
}

async fn revoke_resources(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    tenant: TenantContext,
    resources: &[PreparedTenantResource],
) -> Result<(Vec<TenantResourceIdentity>, String), ExecutorTransactionError> {
    let active = active_binding_map(connection, tenant_id).await?;
    let mut targets = Vec::with_capacity(resources.len());
    for resource in resources {
        let key = ResourceKey::from_identity(&resource.identity);
        let Some(binding) = active.get(&key) else {
            return Err(transaction_conflict("revoke_missing_binding"));
        };
        if binding.resource_digest != resource.identity.digest {
            return Err(transaction_conflict("revoke_digest"));
        }
        targets.push((resource.identity.clone(), binding.locator.clone()));
    }
    let target_keys = targets
        .iter()
        .map(|(identity, _)| ResourceKey::from_identity(identity))
        .collect::<std::collections::BTreeSet<_>>();
    for key in &target_keys {
        TenantResourceRepository::lock_binding_identity_on_connection(
            connection,
            tenant_id,
            kind_name(key.kind),
            &key.resource_id,
        )
        .await
        .map_err(ExecutorTransactionError::Repository)?;
    }
    validate_revoke_dependency_closure(connection, tenant_id, &active, &target_keys).await?;
    targets.sort_by(|left, right| {
        kind_order(right.0.kind)
            .cmp(&kind_order(left.0.kind))
            .then_with(|| left.0.resource_id.cmp(&right.0.resource_id))
    });

    for (identity, locator) in &targets {
        let deactivated = TenantResourceRepository::deactivate_binding_on_connection(
            connection,
            tenant_id,
            kind_name(identity.kind),
            &identity.resource_id,
            &identity.digest,
        )
        .await
        .map_err(map_repository_error)?;
        match deactivated {
            TenantResourceBindingDeactivate::Deactivated(_) => {}
            TenantResourceBindingDeactivate::Conflict(_) => {
                return Err(transaction_conflict("revoke_binding_fence"));
            }
        }
        revoke_locator(
            connection,
            tenant_id,
            tenant,
            identity.kind,
            &identity.resource_id,
            &identity.digest,
            locator,
        )
        .await?;
    }
    let revoked = targets
        .into_iter()
        .map(|(identity, _)| identity)
        .collect::<Vec<_>>();
    let active_after = active_binding_map(connection, tenant_id).await?;
    let remaining = active_after
        .values()
        .filter_map(|binding| {
            parse_kind(&binding.resource_kind).map(|kind| TenantResourceIdentity {
                kind,
                resource_id: binding.resource_id.clone(),
                digest: binding.resource_digest.clone(),
            })
        })
        .collect::<Vec<_>>();
    let digest = canonical_tenant_resource_manifest_sha256(&remaining)
        .map_err(|_| ExecutorTransactionError::Executor(TenantResourceExecutorError::Rejected))?;
    Ok((sort_identities(revoked), digest))
}

#[derive(QueryableByName)]
struct MtlsParentClientRow {
    #[diesel(sql_type = sql_types::Uuid)]
    client_id: Uuid,
}

async fn validate_revoke_dependency_closure(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    active: &BTreeMap<ResourceKey, TenantResourceBinding>,
    targets: &std::collections::BTreeSet<ResourceKey>,
) -> Result<(), ExecutorTransactionError> {
    for (child_key, child) in active {
        if targets.contains(child_key) {
            continue;
        }
        let parent_locator = match child_key.kind {
            TenantResourceKind::Openid4vcDataset => {
                match parse_locator(&child.locator, TenantResourceKind::Openid4vcDataset)? {
                    ResourceLocator::Dataset { subject_id, .. } => user_locator(subject_id),
                    _ => unreachable!(),
                }
            }
            TenantResourceKind::MtlsTrustAnchor => {
                let request_id =
                    parse_uuid_locator(&child.locator, TenantResourceKind::MtlsTrustAnchor)?;
                let parent = sql_query(
                    "SELECT client_id
                     FROM oauth_client_mtls_trust_anchor_requests
                     WHERE tenant_id = $1 AND id = $2
                       AND source = 'operator-managed' AND status = 1",
                )
                .bind::<sql_types::Uuid, _>(tenant_id)
                .bind::<sql_types::Uuid, _>(request_id)
                .get_result::<MtlsParentClientRow>(connection)
                .await
                .map_err(map_diesel_error)?;
                oauth_client_locator(parent.client_id)
            }
            TenantResourceKind::OauthClient => {
                let client_id =
                    parse_uuid_locator(&child.locator, TenantResourceKind::OauthClient)?;
                let public_client =
                    active_public_client_id_on_connection(connection, tenant_id, client_id)
                        .await
                        .map_err(ExecutorTransactionError::Repository)?
                        .ok_or_else(|| transaction_conflict("oauth_client_dependency"))?;
                match TenantResourceRepository::openid4vc_trust_policy_for_client_on_connection(
                    connection,
                    tenant_id,
                    &public_client,
                )
                .await
                .map_err(ExecutorTransactionError::Repository)?
                {
                    Openid4vcTrustPolicyForClient::Active(policy)
                        if targets.contains(&ResourceKey::new(
                            TenantResourceKind::Openid4vcTrustPolicy,
                            &policy.resource_id,
                        )) =>
                    {
                        return Err(ExecutorTransactionError::Executor(
                            TenantResourceExecutorError::Rejected,
                        ));
                    }
                    Openid4vcTrustPolicyForClient::Active(_)
                    | Openid4vcTrustPolicyForClient::BoundInactive
                    | Openid4vcTrustPolicyForClient::Unbound => {}
                }
                continue;
            }
            TenantResourceKind::Openid4vcTrustPolicy | TenantResourceKind::User => continue,
        };
        let parent = active
            .iter()
            .find_map(|(key, binding)| (binding.locator == parent_locator).then_some(key));
        let Some(parent) = parent else {
            return Err(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Unavailable,
            ));
        };
        if targets.contains(parent) {
            return Err(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Rejected,
            ));
        }
    }
    Ok(())
}

async fn revoke_locator(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    tenant: TenantContext,
    kind: TenantResourceKind,
    resource_id: &str,
    expected_digest: &str,
    locator: &str,
) -> Result<(), ExecutorTransactionError> {
    match parse_locator(locator, kind)? {
        ResourceLocator::User(id) => {
            let user_id = nazo_identity::UserId::try_from(id).map_err(|_| {
                ExecutorTransactionError::Executor(TenantResourceExecutorError::Rejected)
            })?;
            let tenant_id = TenantId::try_from(tenant_id).map_err(|_| {
                ExecutorTransactionError::Executor(TenantResourceExecutorError::Rejected)
            })?;
            if !disable_user_on_connection(connection, tenant_id, user_id)
                .await
                .map_err(map_diesel_error)?
            {
                return Err(ExecutorTransactionError::Executor(
                    TenantResourceExecutorError::Rejected,
                ));
            }
        }
        ResourceLocator::OauthClient(id) => {
            if !deactivate_client_on_connection(connection, tenant_id, id)
                .await
                .map_err(map_diesel_error)?
            {
                return Err(ExecutorTransactionError::Executor(
                    TenantResourceExecutorError::Rejected,
                ));
            }
        }
        ResourceLocator::Mtls(request_id) => {
            if !revoke_operator_managed_trust_anchor_on_connection(
                connection,
                tenant.tenant_id,
                request_id,
            )
            .await
            .map_err(map_repository_error)?
            {
                return Err(ExecutorTransactionError::Executor(
                    TenantResourceExecutorError::Rejected,
                ));
            }
        }
        ResourceLocator::Dataset {
            subject_id,
            configuration_id,
        } => {
            if !delete_operator_managed_dataset_on_connection(
                connection,
                tenant_id,
                subject_id,
                &configuration_id,
            )
            .await
            .map_err(map_diesel_error)?
            {
                return Err(ExecutorTransactionError::Executor(
                    TenantResourceExecutorError::Rejected,
                ));
            }
        }
        ResourceLocator::TrustPolicy(policy_id) => {
            let result = TenantResourceRepository::revoke_openid4vc_trust_policy_on_connection(
                connection,
                tenant_id,
                resource_id,
                expected_digest,
            )
            .await
            .map_err(ExecutorTransactionError::Repository)?;
            match result {
                Openid4vcTrustPolicyRevoke::Revoked(policy) if policy.id == policy_id => {}
                Openid4vcTrustPolicyRevoke::Revoked(_) => {
                    return Err(ExecutorTransactionError::Executor(
                        TenantResourceExecutorError::Rejected,
                    ));
                }
                Openid4vcTrustPolicyRevoke::Conflict(_) => {
                    return Err(transaction_conflict("trust_policy_revoke_digest"));
                }
                Openid4vcTrustPolicyRevoke::AlreadyAbsent => {
                    return Err(ExecutorTransactionError::Executor(
                        TenantResourceExecutorError::Rejected,
                    ));
                }
            }
        }
    }
    Ok(())
}

fn is_operator_locator(locator: &str, kind: TenantResourceKind) -> bool {
    parse_locator(locator, kind).is_ok()
}

/// Authoritative read-only enumeration.  Returns the selector-filtered,
/// sorted identity set plus the complete active set so callers can assert
/// manifest consistency without a second read.
async fn enumerate_resources(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    selectors: &[TenantResourceSelector],
) -> Result<(Vec<TenantResourceIdentity>, Vec<TenantResourceIdentity>), ExecutorTransactionError> {
    let active = TenantResourceRepository::active_bindings_on_connection(connection, tenant_id)
        .await
        .map_err(map_repository_error)?;
    let selected = |binding: &TenantResourceBinding| {
        selectors.is_empty()
            || selectors.iter().any(|selector| {
                kind_name(selector.kind) == binding.resource_kind
                    && selector.resource_id == binding.resource_id
            })
    };
    let mut result = Vec::new();
    let mut complete = Vec::new();
    for binding in active.into_iter() {
        let kind = parse_kind(&binding.resource_kind).ok_or(ExecutorTransactionError::Executor(
            TenantResourceExecutorError::Unavailable,
        ))?;
        complete.push(TenantResourceIdentity {
            kind,
            resource_id: binding.resource_id.clone(),
            digest: binding.resource_digest.clone(),
        });
        if selected(&binding) {
            result.push(TenantResourceIdentity {
                kind,
                resource_id: binding.resource_id,
                digest: binding.resource_digest,
            });
        }
        if complete.len() > nazo_operator_protocol::MAX_TENANT_RESOURCE_IDENTITIES
            || result.len() > nazo_operator_protocol::MAX_TENANT_RESOURCE_IDENTITIES
        {
            return Err(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::TooLarge,
            ));
        }
    }
    Ok((sort_identities(result), sort_identities(complete)))
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct ResourceKey {
    kind: TenantResourceKind,
    resource_id: String,
}

impl ResourceKey {
    fn new(kind: TenantResourceKind, resource_id: &str) -> Self {
        Self {
            kind,
            resource_id: resource_id.to_owned(),
        }
    }

    fn from_identity(identity: &TenantResourceIdentity) -> Self {
        Self::new(identity.kind, &identity.resource_id)
    }
}

async fn active_binding_map(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
) -> Result<BTreeMap<ResourceKey, TenantResourceBinding>, ExecutorTransactionError> {
    let mut map = BTreeMap::new();
    for binding in TenantResourceRepository::active_bindings_on_connection(connection, tenant_id)
        .await
        .map_err(map_repository_error)?
    {
        let Some(kind) = parse_kind(&binding.resource_kind) else {
            return Err(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Unavailable,
            ));
        };
        map.insert(ResourceKey::new(kind, &binding.resource_id), binding);
    }
    Ok(map)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ResourceLocator {
    User(Uuid),
    OauthClient(Uuid),
    Mtls(Uuid),
    TrustPolicy(Uuid),
    Dataset {
        subject_id: Uuid,
        configuration_id: String,
    },
}

fn parse_locator(
    locator: &str,
    expected_kind: TenantResourceKind,
) -> Result<ResourceLocator, ExecutorTransactionError> {
    let mut parts = locator.split('/');
    let prefix = parts.next().unwrap_or_default();
    let value = parts.next().unwrap_or_default();
    let result = match (prefix, expected_kind) {
        ("user", TenantResourceKind::User) if parts.next().is_none() => {
            Uuid::parse_str(value).ok().map(ResourceLocator::User)
        }
        ("oauth-client", TenantResourceKind::OauthClient) if parts.next().is_none() => {
            Uuid::parse_str(value)
                .ok()
                .map(ResourceLocator::OauthClient)
        }
        ("mtls-trust-anchor", TenantResourceKind::MtlsTrustAnchor) if parts.next().is_none() => {
            Uuid::parse_str(value).ok().map(ResourceLocator::Mtls)
        }
        ("openid4vc-trust-policy", TenantResourceKind::Openid4vcTrustPolicy)
            if parts.next().is_none() =>
        {
            Uuid::parse_str(value)
                .ok()
                .map(ResourceLocator::TrustPolicy)
        }
        ("openid4vc-dataset", TenantResourceKind::Openid4vcDataset) => {
            let configuration = parts.collect::<Vec<_>>().join("/");
            Uuid::parse_str(value).ok().and_then(|subject_id| {
                (!configuration.is_empty()).then_some(ResourceLocator::Dataset {
                    subject_id,
                    configuration_id: configuration,
                })
            })
        }
        _ => None,
    };
    result.ok_or(ExecutorTransactionError::Executor(
        TenantResourceExecutorError::Rejected,
    ))
}

fn parse_uuid_locator(
    locator: &str,
    kind: TenantResourceKind,
) -> Result<Uuid, ExecutorTransactionError> {
    match parse_locator(locator, kind)? {
        ResourceLocator::User(id)
        | ResourceLocator::OauthClient(id)
        | ResourceLocator::Mtls(id)
        | ResourceLocator::TrustPolicy(id) => Ok(id),
        ResourceLocator::Dataset { .. } => Err(ExecutorTransactionError::Executor(
            TenantResourceExecutorError::Rejected,
        )),
    }
}

fn user_locator(id: Uuid) -> String {
    format!("user/{id}")
}

fn oauth_client_locator(id: Uuid) -> String {
    format!("oauth-client/{id}")
}

fn mtls_locator(id: Uuid) -> String {
    format!("mtls-trust-anchor/{id}")
}

fn trust_policy_locator(id: Uuid) -> String {
    format!("openid4vc-trust-policy/{id}")
}

fn dataset_locator(subject_id: Uuid, configuration_id: &str) -> String {
    format!("openid4vc-dataset/{subject_id}/{configuration_id}")
}

fn kind_name(kind: TenantResourceKind) -> &'static str {
    match kind {
        TenantResourceKind::OauthClient => "oauth-client",
        TenantResourceKind::MtlsTrustAnchor => "mtls-trust-anchor",
        TenantResourceKind::Openid4vcDataset => "openid4vc-dataset",
        TenantResourceKind::Openid4vcTrustPolicy => "openid4vc-trust-policy",
        TenantResourceKind::User => "user",
    }
}

fn parse_kind(value: &str) -> Option<TenantResourceKind> {
    match value {
        "oauth-client" => Some(TenantResourceKind::OauthClient),
        "mtls-trust-anchor" => Some(TenantResourceKind::MtlsTrustAnchor),
        "openid4vc-dataset" => Some(TenantResourceKind::Openid4vcDataset),
        "openid4vc-trust-policy" => Some(TenantResourceKind::Openid4vcTrustPolicy),
        "user" => Some(TenantResourceKind::User),
        _ => None,
    }
}

fn identity_sort_key(identity: &TenantResourceIdentity) -> (u8, &str) {
    (kind_order(identity.kind), &identity.resource_id)
}

fn kind_order(kind: TenantResourceKind) -> u8 {
    match kind {
        TenantResourceKind::User => 0,
        TenantResourceKind::OauthClient => 1,
        TenantResourceKind::MtlsTrustAnchor => 2,
        TenantResourceKind::Openid4vcDataset => 3,
        TenantResourceKind::Openid4vcTrustPolicy => 4,
    }
}

fn sort_identities(mut identities: Vec<TenantResourceIdentity>) -> Vec<TenantResourceIdentity> {
    identities.sort_by(|left, right| identity_sort_key(left).cmp(&identity_sort_key(right)));
    identities
}

#[derive(Clone, Default, Eq, PartialEq)]
struct ProfileFields {
    display_name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    middle_name: Option<String>,
    nickname: Option<String>,
    profile_url: Option<String>,
    avatar_url: Option<String>,
    website_url: Option<String>,
    gender: Option<String>,
    birthdate: Option<String>,
    zoneinfo: Option<String>,
    locale: Option<String>,
    address_formatted: Option<String>,
    address_street_address: Option<String>,
    address_locality: Option<String>,
    address_region: Option<String>,
    address_postal_code: Option<String>,
    address_country: Option<String>,
    phone_number: Option<String>,
    phone_number_verified: bool,
}

fn profile_fields(value: Option<&Value>) -> Result<ProfileFields, ()> {
    let Some(value) = value else {
        return Ok(ProfileFields::default());
    };
    let Some(object) = value.as_object() else {
        return Err(());
    };
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "display_name"
                | "given_name"
                | "family_name"
                | "middle_name"
                | "nickname"
                | "profile_url"
                | "avatar_url"
                | "website_url"
                | "gender"
                | "birthdate"
                | "zoneinfo"
                | "locale"
                | "address_formatted"
                | "address_street_address"
                | "address_locality"
                | "address_region"
                | "address_postal_code"
                | "address_country"
                | "phone_number"
                | "phone_number_verified"
        )
    }) {
        return Err(());
    }
    let mut fields = ProfileFields::default();
    macro_rules! text {
        ($name:ident, $max:expr) => {
            fields.$name = profile_text(object.get(stringify!($name)), $max)?;
        };
    }
    text!(display_name, 80);
    text!(given_name, 80);
    text!(family_name, 80);
    text!(middle_name, 80);
    text!(nickname, 80);
    text!(profile_url, 512);
    text!(avatar_url, 512);
    text!(website_url, 512);
    text!(gender, 40);
    text!(birthdate, 10);
    text!(zoneinfo, 64);
    text!(locale, 35);
    text!(address_formatted, 512);
    text!(address_street_address, 256);
    text!(address_locality, 128);
    text!(address_region, 128);
    text!(address_postal_code, 64);
    text!(address_country, 64);
    text!(phone_number, 32);
    if let Some(value) = object.get("phone_number_verified") {
        fields.phone_number_verified = value.as_bool().ok_or(())?;
    }
    Ok(fields)
}

fn profile_text(value: Option<&Value>, max_bytes: usize) -> Result<Option<String>, ()> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let text = value.as_str().ok_or(())?;
    if text.is_empty() || text.len() > max_bytes || text.chars().any(char::is_control) {
        return Err(());
    }
    Ok(Some(text.to_owned()))
}

/// Build the append-only security-audit event for one executed tenant-resource
/// frame. Explicit fields keep the audit shape independent from the wire type.
#[allow(clippy::too_many_arguments)]
fn tenant_resource_audit_event(
    deployment_id: &str,
    tenant_id: &str,
    jti: &str,
    request_sha256: &str,
    actor: &Value,
    operation: TenantResourceAction,
    expected_revision: u64,
    resource_manifest_sha256: &str,
    resources: &[TenantResourceIdentity],
) -> nazo_postgres::SecurityAuditEvent {
    nazo_postgres::SecurityAuditEvent {
        event_id: Uuid::now_v7(),
        event_type: format!("tenant_resource_{}", operation_name(operation)),
        event_category: "tenant_resource".to_owned(),
        payload: json!({
            "deployment_id": deployment_id,
            "tenant_id": tenant_id,
            "jti": jti,
            "request_sha256": request_sha256,
            "actor": actor,
            "operation": operation_name(operation),
            "expected_revision": expected_revision,
            "resource_manifest_sha256": resource_manifest_sha256,
            "resources": resources,
        }),
        occurred_at: Utc::now(),
    }
}

fn operation_name(operation: TenantResourceAction) -> &'static str {
    match operation {
        TenantResourceAction::Apply => "apply",
        TenantResourceAction::Enumerate => "enumerate",
        TenantResourceAction::Revoke => "revoke",
    }
}

#[derive(Debug)]
enum ExecutorTransactionError {
    Executor(TenantResourceExecutorError),
    Repository(RepositoryError),
    Diesel(diesel::result::Error),
}

fn transaction_conflict(stage: &'static str) -> ExecutorTransactionError {
    tracing::debug!(
        stage,
        "tenant-resource operation rejected by a consistency fence"
    );
    ExecutorTransactionError::Executor(TenantResourceExecutorError::Conflict)
}

impl From<TenantResourceExecutorError> for ExecutorTransactionError {
    fn from(error: TenantResourceExecutorError) -> Self {
        Self::Executor(error)
    }
}

impl From<diesel::result::Error> for ExecutorTransactionError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Diesel(error)
    }
}

fn map_transaction_error(error: ExecutorTransactionError) -> TenantResourceExecutorError {
    match error {
        ExecutorTransactionError::Executor(error) => error,
        ExecutorTransactionError::Repository(error) => map_repository_error(error),
        ExecutorTransactionError::Diesel(error) => diesel_executor_error(error),
    }
}

fn map_repository_error(error: RepositoryError) -> TenantResourceExecutorError {
    match error {
        RepositoryError::Conflict => TenantResourceExecutorError::Conflict,
        RepositoryError::Unavailable | RepositoryError::NotFound => {
            TenantResourceExecutorError::Unavailable
        }
        RepositoryError::AlreadyProcessed => TenantResourceExecutorError::Rejected,
        RepositoryError::Consistency(_) | RepositoryError::Unexpected(_) => {
            TenantResourceExecutorError::Unavailable
        }
    }
}

fn map_diesel_error(error: diesel::result::Error) -> ExecutorTransactionError {
    ExecutorTransactionError::Executor(diesel_executor_error(error))
}

fn diesel_executor_error(error: diesel::result::Error) -> TenantResourceExecutorError {
    match error {
        diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        ) => TenantResourceExecutorError::Conflict,
        diesel::result::Error::NotFound => TenantResourceExecutorError::Rejected,
        _ => TenantResourceExecutorError::Unavailable,
    }
}

fn map_preparation_error(error: TenantResourcePreparationError) -> TenantResourceExecutorError {
    match error {
        TenantResourcePreparationError::Rejected => TenantResourceExecutorError::Rejected,
        TenantResourcePreparationError::Unavailable => TenantResourceExecutorError::Unavailable,
    }
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
#[path = "../tests/unit/tenant_resource_executor.rs"]
mod tests;
