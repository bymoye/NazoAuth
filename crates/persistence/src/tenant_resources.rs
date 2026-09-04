//! Atomic tenant-resource persistence contract.
//!
//! An adapter must commit idempotency, resource mutations, revision fencing,
//! security audit append, and the replayable typed outcome as one atomic unit.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use futures_util::future::BoxFuture;
use nazo_auth::{CreateClientRequest, OAuthClient};
use nazo_identity::TenantContext;
use nazo_operator_protocol::{
    ControlResultData, Openid4vcTrustPolicy, ProtocolError, TenantResourceIdentity,
    TenantResourceKind, TenantResourceMapping, TenantResourceSelector,
    canonical_tenant_resource_manifest_sha256, validate_control_result_data_for_wire,
    validate_openid4vc_trust_policy,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

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
pub enum TenantResourceAction {
    Apply,
    Enumerate,
    Revoke,
}

#[derive(Clone)]
pub enum TenantResourcePayload {
    User(Box<UserResourcePayload>),
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
    pub profile: UserProfileFields,
}

#[derive(Clone, Default, Eq, PartialEq)]
pub struct UserProfileFields {
    pub display_name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub middle_name: Option<String>,
    pub nickname: Option<String>,
    pub profile_url: Option<String>,
    pub avatar_url: Option<String>,
    pub website_url: Option<String>,
    pub gender: Option<String>,
    pub birthdate: Option<String>,
    pub zoneinfo: Option<String>,
    pub locale: Option<String>,
    pub address_formatted: Option<String>,
    pub address_street_address: Option<String>,
    pub address_locality: Option<String>,
    pub address_region: Option<String>,
    pub address_postal_code: Option<String>,
    pub address_country: Option<String>,
    pub phone_number: Option<String>,
    pub phone_number_verified: bool,
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

/// Decode an Apply manifest and bind every payload to the exact signed
/// identity set. This validation is backend independent.
pub fn decode_change_set_payloads(
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
            let profile = normalize_user_profile(value.profile.as_ref())?;
            Ok(TenantResourcePayload::User(Box::new(UserResourcePayload {
                username: value.username,
                email: value.email,
                password: value.password,
                email_verified: value.email_verified,
                profile,
            })))
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

fn normalize_user_profile(
    value: Option<&Value>,
) -> Result<UserProfileFields, TenantResourceExecutorError> {
    let Some(value) = value else {
        return Ok(UserProfileFields::default());
    };
    let Some(object) = value.as_object() else {
        return Err(TenantResourceExecutorError::InvalidPayload(
            "invalid user profile",
        ));
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
        return Err(TenantResourceExecutorError::InvalidPayload(
            "invalid user profile",
        ));
    }
    let mut fields = UserProfileFields::default();
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
        fields.phone_number_verified =
            value
                .as_bool()
                .ok_or(TenantResourceExecutorError::InvalidPayload(
                    "invalid user profile",
                ))?;
    }
    Ok(fields)
}

fn profile_text(
    value: Option<&Value>,
    max_bytes: usize,
) -> Result<Option<String>, TenantResourceExecutorError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let text = value
        .as_str()
        .ok_or(TenantResourceExecutorError::InvalidPayload(
            "invalid user profile",
        ))?;
    if text.is_empty() || text.len() > max_bytes || text.chars().any(char::is_control) {
        return Err(TenantResourceExecutorError::InvalidPayload(
            "invalid user profile",
        ));
    }
    Ok(Some(text.to_owned()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Result of application policy preparation consumed by a persistence adapter.
pub struct PreparedOAuthClient {
    pub client: OAuthClient,
    pub client_secret_hash: Option<String>,
}

/// Certificate material validated by the application policy layer before the
/// adapter opens its mutation transaction.
pub struct PreparedMtlsTrustAnchor {
    pub certificate_pem: String,
    pub certificate_sha256: String,
    pub subject_dn: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TenantResourcePreparationError {
    Rejected,
    Unavailable,
}

/// Application policy bridge used before entering the database transaction.
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

    fn prepare_mtls_trust_anchor<'a>(
        &'a self,
        certificate_pem: String,
    ) -> BoxFuture<'a, Result<PreparedMtlsTrustAnchor, TenantResourcePreparationError>>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlTenantResourceOutcome {
    pub revision: u64,
    pub resources: Vec<TenantResourceIdentity>,
    pub resource_mappings: Vec<TenantResourceMapping>,
    pub resource_manifest_sha256: String,
}

impl ControlTenantResourceOutcome {
    #[must_use]
    pub fn control_result_data(&self, operation: TenantResourceAction) -> ControlResultData {
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

pub struct ControlTenantResourceFrame<'a> {
    pub deployment_id: &'a str,
    pub jti: &'a str,
    pub request_sha256: &'a str,
    pub actor: &'a Value,
    pub operation: TenantResourceAction,
    pub tenant_id: &'a str,
    pub resources: Vec<PreparedTenantResource>,
    pub selectors: &'a [TenantResourceSelector],
}

/// Atomic execution boundary implemented by each database adapter.
pub trait TenantResourceExecutorPort: Send + Sync {
    fn execute_control_operation<'a>(
        &'a self,
        frame: ControlTenantResourceFrame<'a>,
    ) -> BoxFuture<'a, Result<ControlTenantResourceOutcome, TenantResourceExecutorError>>;
}

#[must_use]
pub fn empty_manifest_sha256() -> String {
    canonical_tenant_resource_manifest_sha256(&[])
        .expect("the empty tenant-resource identity set is valid")
}

pub fn validate_control_outcome(
    operation: TenantResourceAction,
    outcome: &ControlTenantResourceOutcome,
) -> Result<(), TenantResourceExecutorError> {
    validate_control_result_data_for_wire(&outcome.control_result_data(operation)).map_err(
        |error| match error {
            ProtocolError::TooLarge => TenantResourceExecutorError::TooLarge,
            _ => TenantResourceExecutorError::Rejected,
        },
    )
}

#[must_use]
pub const fn operation_name(operation: TenantResourceAction) -> &'static str {
    match operation {
        TenantResourceAction::Apply => "apply",
        TenantResourceAction::Enumerate => "enumerate",
        TenantResourceAction::Revoke => "revoke",
    }
}

#[cfg(test)]
#[path = "../tests/unit/tenant_resources.rs"]
mod tests;
