use super::helpers::*;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use chrono::{Duration, Utc};
use nazo_auth::{
    DpopError, DpopNoncePolicy, DpopProofRequest, issue_authorization_server_dpop_nonce,
    token_audience_contains, validate_authorization_server_dpop,
};
use nazo_digital_credentials::{
    CredentialSignerPort, EphemeralEncryptionKey, encrypt_ecdh_es, encrypt_ecdh_es_deflate,
};
use nazo_identity::{TenantId, UserId};
use nazo_openid4vc_http_actix::{
    AccessTokenScheme, CreateCredentialOfferRequest, CreateCredentialOfferResponse,
    CredentialEndpointResponse, CredentialHttpError, CredentialIssuerFuture,
    CredentialIssuerOperations, CredentialRequestBody, CredentialRequestContext,
    CredentialResponseBody, PreAuthorizedTokenRequest, PreAuthorizedTokenResponse,
};
use nazo_openid4vci::{
    AuthorizationCodeGrant, BatchCredentialIssuance, CredentialAccess, CredentialConfiguration,
    CredentialIssuance, CredentialIssuerMetadata, CredentialIssuerService, CredentialOffer,
    CredentialOfferGrants, CredentialRequest, CredentialRequestEncryptionMetadata,
    CredentialResponse, CredentialResponseEncryption, CredentialStorePort,
    DeferredCredentialRequest, DeferredPayload, EncryptionMetadata, IssuanceDisposition,
    IssuanceNotification, NonceRecord, NotificationRequest, PreAuthorizedCodeGrant,
    TxCodeDescription,
};
use nazo_runtime_modules::ModuleId;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    adapters::security::{
        blake3_hex, constant_time_eq, hash_password_blocking_limited, random_urlsafe_token,
    },
    domain::{
        Openid4vcClientAttestationValidator, Openid4vcCredentialCrypto, Openid4vcProofValidator,
    },
    http::{authorization::ServerAuthorizationService, token::ServerTokenService},
    runtime_modules::ServerRuntimeModuleRegistry,
};

mod dataset;
mod issuance;
mod offers;

use dataset::Openid4vcDataset;
pub(crate) use dataset::{
    openid4vci_authorization_detail, openid4vci_configuration_id_from_identifier,
    token_endpoint_dpop_target_uris,
};

type VciService = CredentialIssuerService<
    nazo_postgres::Openid4vciRepository,
    Openid4vcProofValidator,
    Openid4vcDataset,
    Openid4vcCredentialCrypto,
>;

/// Issuer administration input. OpenID4VCI does not define this control-plane object.
#[derive(Clone, Debug, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PutCredentialDatasetRequest {
    pub claims: Value,
    #[serde(default)]
    pub valid_from: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub valid_until: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub(crate) struct CredentialDatasetResponse {
    pub subject_id: Uuid,
    pub credential_configuration_id: String,
    pub claims: Value,
    pub valid_from: Option<chrono::DateTime<chrono::Utc>>,
    pub valid_until: Option<chrono::DateTime<chrono::Utc>>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

pub(crate) struct ServerCredentialIssuerOperations {
    store: nazo_postgres::Openid4vciRepository,
    service: VciService,
    token_service: Arc<ServerTokenService>,
    authorization: Arc<ServerAuthorizationService>,
    pub(super) runtime: Arc<ServerRuntimeModuleRegistry>,
    crypto: Openid4vcCredentialCrypto,
    request_encryption: EphemeralEncryptionKey,
    issuer: String,
    pub(super) configurations: Arc<BTreeMap<String, CredentialConfiguration>>,
    deferred_configurations: Arc<BTreeSet<String>>,
    dpop_nonce_policy: DpopNoncePolicy,
    client_attestation: Option<Arc<Openid4vcClientAttestationValidator>>,
    pub(super) users: nazo_postgres::UserRepository,
    pub(super) datasets: nazo_postgres::Openid4vciDatasetRepository,
    pub(super) tenant_id: Uuid,
}

#[allow(clippy::too_many_arguments)]
impl ServerCredentialIssuerOperations {
    pub(crate) fn new(
        pool: nazo_postgres::DbPool,
        tenant_id: Uuid,
        data_key: [u8; 32],
        token_service: Arc<ServerTokenService>,
        authorization: Arc<ServerAuthorizationService>,
        runtime: Arc<ServerRuntimeModuleRegistry>,
        crypto: Openid4vcCredentialCrypto,
        proof_validator: Openid4vcProofValidator,
        client_attestation: Option<Arc<Openid4vcClientAttestationValidator>>,
        issuer: String,
        configurations: BTreeMap<String, CredentialConfiguration>,
        deferred_configurations: BTreeSet<String>,
        dpop_nonce_policy: DpopNoncePolicy,
    ) -> anyhow::Result<Self> {
        let configurations = Arc::new(configurations);
        let store = nazo_postgres::Openid4vciRepository::new(pool.clone(), data_key);
        let users = nazo_postgres::UserRepository::new(pool.clone());
        let datasets = nazo_postgres::Openid4vciDatasetRepository::new(pool.clone(), data_key);
        let service = CredentialIssuerService::new(
            store.clone(),
            proof_validator,
            Openid4vcDataset {
                store: datasets.clone(),
            },
            crypto.clone(),
            issuer.clone(),
            10,
        );
        Ok(Self {
            store,
            service,
            token_service,
            authorization,
            runtime,
            crypto,
            request_encryption: EphemeralEncryptionKey::derive(
                &data_key,
                b"credential-request-encryption",
            )?,
            issuer,
            configurations,
            deferred_configurations: Arc::new(deferred_configurations),
            dpop_nonce_policy,
            client_attestation,
            users,
            datasets,
            tenant_id,
        })
    }

    pub(super) fn enabled(&self, admission: nazo_auth::CapabilityAdmission) -> bool {
        nazo_auth::module_admissible(
            &self.runtime.snapshot(),
            ModuleId::Openid4vciIssuer,
            admission,
        )
    }

    fn metadata_document(&self) -> CredentialIssuerMetadata {
        let mut request_key = self.request_encryption.public_jwk();
        request_key["kid"] = json!("openid4vci-request-encryption");
        request_key["alg"] = json!("ECDH-ES");
        CredentialIssuerMetadata {
            credential_issuer: self.issuer.clone(),
            authorization_servers: vec![self.issuer.clone()],
            credential_endpoint: format!("{}/openid4vci/credential", self.issuer),
            nonce_endpoint: Some(format!("{}/openid4vci/nonce", self.issuer)),
            deferred_credential_endpoint: Some(format!(
                "{}/openid4vci/deferred_credential",
                self.issuer
            )),
            notification_endpoint: Some(format!("{}/openid4vci/notification", self.issuer)),
            credential_request_encryption: Some(CredentialRequestEncryptionMetadata {
                jwks: Some(json!({"keys": [request_key]})),
                enc_values_supported: vec!["A256GCM".to_owned()],
                zip_values_supported: vec!["DEF".to_owned()],
                encryption_required: false,
            }),
            credential_response_encryption: Some(EncryptionMetadata {
                jwks: None,
                alg_values_supported: vec!["ECDH-ES".to_owned()],
                enc_values_supported: vec!["A256GCM".to_owned()],
                zip_values_supported: vec!["DEF".to_owned()],
                encryption_required: false,
            }),
            batch_credential_issuance: Some(BatchCredentialIssuance { batch_size: 10 }),
            display: Vec::new(),
            credential_configurations_supported: self.configurations.as_ref().clone(),
            signed_metadata: None,
        }
    }

    async fn request_json<T: serde::de::DeserializeOwned>(
        &self,
        body: CredentialRequestBody<T>,
    ) -> Result<T, CredentialHttpError> {
        match body {
            CredentialRequestBody::Json(value) => Ok(value),
            CredentialRequestBody::Jwt(value) => {
                let plaintext = self
                    .request_encryption
                    .decrypt_credential_request(&value, "openid4vci-request-encryption")
                    .map_err(|_| {
                        vci_error(
                            400,
                            "invalid_encryption_parameters",
                            "Credential request encryption is invalid.",
                        )
                    })?;
                serde_json::from_slice(&plaintext).map_err(|_| {
                    vci_error(
                        400,
                        "invalid_credential_request",
                        "Encrypted credential request is malformed.",
                    )
                })
            }
        }
    }

    async fn access(
        &self,
        context: &CredentialRequestContext,
    ) -> Result<CredentialAccess, CredentialHttpError> {
        let claims = self
            .token_service
            .decode_access_token(&self.issuer, &context.bearer_token)
            .await
            .map_err(|_| {
                vci_error(
                    503,
                    "invalid_token",
                    "Access token validation is unavailable.",
                )
            })?
            .ok_or_else(|| vci_error(401, "invalid_token", "Access token is invalid."))?;
        if !token_audience_contains(&claims.aud, &self.issuer) {
            return Err(vci_error(
                401,
                "invalid_token",
                "Access token is not intended for this credential issuer.",
            ));
        }
        let tenant_id = Uuid::parse_str(&claims.tenant_id)
            .map_err(|_| vci_error(401, "invalid_token", "Access token tenant is invalid."))?;
        if tenant_id != self.tenant_id {
            return Err(vci_error(
                401,
                "invalid_token",
                "Access token tenant does not match this credential issuer.",
            ));
        }
        if self
            .token_service
            .access_token_revoked(tenant_id, &claims.jti)
            .await
            .unwrap_or(true)
        {
            return Err(vci_error(401, "invalid_token", "Access token is revoked."));
        }
        let subject_id = match claims
            .user_id
            .as_deref()
            .and_then(|value| Uuid::parse_str(value).ok())
            .or_else(|| Uuid::parse_str(&claims.sub).ok())
        {
            Some(value) => value,
            None => self
                .token_service
                .load_access_token_subject(tenant_id, &claims.jti)
                .await
                .map_err(|_| {
                    vci_error(
                        503,
                        "invalid_token",
                        "Access token subject state is unavailable.",
                    )
                })?
                .ok_or_else(|| {
                    vci_error(401, "invalid_token", "Access token subject is invalid.")
                })?,
        };
        let (dpop_jkt, mtls_x5t_s256) = claims
            .cnf
            .as_ref()
            .map_or((None, None), |cnf| (cnf.jkt.clone(), cnf.x5t_s256.clone()));
        match (
            dpop_jkt.as_deref(),
            mtls_x5t_s256.as_deref(),
            context.access_token_scheme,
            context.dpop_proof.as_deref(),
        ) {
            (Some(_), None, AccessTokenScheme::Dpop, Some(_)) => {}
            (None, Some(expected), AccessTokenScheme::Bearer, None) => {
                let Some(actual) = context.mtls_x5t_s256.as_deref() else {
                    return Err(vci_error(
                        401,
                        "invalid_token",
                        "A mTLS-bound access token requires the matching client certificate.",
                    ));
                };
                if !constant_time_eq(expected.as_bytes(), actual.as_bytes()) {
                    return Err(vci_error(
                        401,
                        "invalid_token",
                        "The mTLS client certificate does not match the access token.",
                    ));
                }
            }
            (None, None, AccessTokenScheme::Bearer, None) => {}
            (Some(_), Some(_), _, _) => {
                return Err(vci_error(
                    401,
                    "invalid_token",
                    "Access token contains conflicting sender constraints.",
                ));
            }
            (Some(_), None, _, _) => {
                return Err(vci_error(
                    401,
                    "invalid_token",
                    "A DPoP-bound access token requires the DPoP authorization scheme and proof.",
                ));
            }
            (None, Some(_), _, _) => {
                return Err(vci_error(
                    401,
                    "invalid_token",
                    "A mTLS-bound access token requires the matching client certificate.",
                ));
            }
            (None, None, _, _) => {
                return Err(vci_error(
                    401,
                    "invalid_dpop_proof",
                    "An unbound access token cannot be presented with DPoP.",
                ));
            }
        }
        if dpop_jkt.is_some() {
            let target = format!(
                "{}{}",
                self.issuer.trim_end_matches('/'),
                context.request_url
            );
            validate_authorization_server_dpop(
                self.authorization.as_ref(),
                DpopProofRequest {
                    proof: context.dpop_proof.as_deref(),
                    method: context.method,
                    target_uris: &[target.as_str()],
                    access_token: Some(&context.bearer_token),
                    expected_jkt: dpop_jkt.as_deref(),
                },
                self.dpop_nonce_policy,
            )
            .await
            .map_err(|error| match error {
                DpopError::UseNonce(nonce) => CredentialHttpError {
                    status: 401,
                    error: "use_dpop_nonce",
                    description: "Credential issuer requires nonce in DPoP proof.",
                    dpop_nonce: Some(nonce),
                },
                DpopError::NonceStoreUnavailable => {
                    vci_error(503, "server_error", "DPoP nonce validation is unavailable.")
                }
                _ => vci_error(401, "invalid_dpop_proof", "DPoP proof is invalid."),
            })?;
        }
        let (configuration_ids, credential_identifiers) = authorized_credentials(
            &claims.authorization_details,
            &claims.scope,
            &self.issuer,
            &self.configurations,
        )?;
        let token_id = Uuid::parse_str(&claims.jti)
            .map_err(|_| vci_error(401, "invalid_token", "Access token identifier is invalid."))?;
        let access = CredentialAccess {
            token_id,
            tenant_id,
            subject_id,
            client_id: claims.client_id,
            configuration_ids,
            credential_identifiers,
            dpop_jkt,
            expires_at: chrono::DateTime::from_timestamp(claims.exp, 0).ok_or_else(|| {
                vci_error(401, "invalid_token", "Access token expiry is invalid.")
            })?,
        };
        self.store
            .upsert_access(&blake3_hex(&context.bearer_token), &access)
            .await
            .map_err(|_| {
                vci_error(
                    503,
                    "server_error",
                    "Credential access state is unavailable.",
                )
            })?;
        Ok(access)
    }

    async fn finish_response(
        &self,
        response: CredentialResponse,
        encryption: Option<&CredentialResponseEncryption>,
    ) -> Result<CredentialResponseBody, CredentialHttpError> {
        if let Some(encryption) = encryption {
            if encryption.jwk.get("alg").and_then(Value::as_str) != Some("ECDH-ES")
                || encryption.enc != "A256GCM"
                || encryption.zip.as_deref().is_some_and(|zip| zip != "DEF")
            {
                return Err(vci_error(
                    400,
                    "invalid_encryption_parameters",
                    "Credential response encryption parameters are unsupported.",
                ));
            }
            let bytes = serde_json::to_vec(&response).map_err(|_| {
                vci_error(500, "server_error", "Credential response encoding failed.")
            })?;
            let encrypted = if encryption.zip.as_deref() == Some("DEF") {
                encrypt_ecdh_es_deflate(&bytes, &encryption.jwk, Some("application/json"))
            } else {
                encrypt_ecdh_es(&bytes, &encryption.jwk, Some("application/json"))
            };
            return encrypted.map(CredentialResponseBody::Jwt).map_err(|_| {
                vci_error(
                    400,
                    "invalid_encryption_parameters",
                    "Credential response encryption key is invalid.",
                )
            });
        }
        Ok(CredentialResponseBody::Json(response))
    }

    async fn next_dpop_nonce(
        &self,
        access: &CredentialAccess,
    ) -> Result<Option<String>, CredentialHttpError> {
        if access.dpop_jkt.is_none() {
            return Ok(None);
        }
        issue_authorization_server_dpop_nonce(self.authorization.as_ref())
            .await
            .map(Some)
            .map_err(|_| vci_error(503, "server_error", "DPoP nonce issuance is unavailable."))
    }
}

impl CredentialIssuerOperations for ServerCredentialIssuerOperations {
    fn metadata(
        &self,
    ) -> CredentialIssuerFuture<'_, Result<CredentialIssuerMetadata, CredentialHttpError>> {
        Box::pin(async move {
            if !self.enabled(nazo_auth::CapabilityAdmission::ExistingTransaction) {
                return Err(vci_error(
                    404,
                    "invalid_request",
                    "Credential issuer is disabled.",
                ));
            }
            let mut metadata = self.metadata_document();
            let now = Utc::now().timestamp();
            let mut signed = serde_json::to_value(&metadata)
                .map_err(|_| vci_error(500, "server_error", "Metadata encoding failed."))?;
            signed["iss"] = json!(self.issuer);
            signed["sub"] = json!(self.issuer);
            signed["iat"] = json!(now);
            signed["exp"] = json!(now + 300);
            metadata.signed_metadata = Some(
                self.crypto
                    .sign_issuer_metadata(&signed)
                    .await
                    .map_err(|_| vci_error(503, "server_error", "Metadata signing failed."))?,
            );
            Ok(metadata)
        })
    }

    fn offer<'a>(
        &'a self,
        offer_id: &'a str,
    ) -> CredentialIssuerFuture<'a, Result<CredentialOffer, CredentialHttpError>> {
        self.offer_operation(offer_id)
    }

    fn nonce(
        &self,
        _dpop_proof: Option<&str>,
    ) -> CredentialIssuerFuture<'_, Result<String, CredentialHttpError>> {
        Box::pin(async move {
            if !self.enabled(nazo_auth::CapabilityAdmission::NewRequest) {
                return Err(vci_error(
                    404,
                    "invalid_request",
                    "Credential issuer is disabled.",
                ));
            }
            let nonce = random_urlsafe_token();
            self.store
                .issue_nonce(&NonceRecord {
                    nonce_hash: blake3_hex(&nonce),
                    expires_at: Utc::now() + Duration::minutes(5),
                })
                .await
                .map_err(|_| {
                    vci_error(
                        503,
                        "server_error",
                        "Credential nonce state is unavailable.",
                    )
                })?;
            Ok(nonce)
        })
    }

    fn credential<'a>(
        &'a self,
        context: CredentialRequestContext,
        body: CredentialRequestBody<CredentialRequest>,
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        self.credential_operation(context, body)
    }

    fn deferred<'a>(
        &'a self,
        context: CredentialRequestContext,
        body: CredentialRequestBody<DeferredCredentialRequest>,
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        self.deferred_operation(context, body)
    }

    fn notify<'a>(
        &'a self,
        context: CredentialRequestContext,
        request: NotificationRequest,
    ) -> CredentialIssuerFuture<'a, Result<CredentialEndpointResponse<()>, CredentialHttpError>>
    {
        self.notify_operation(context, request)
    }

    fn pre_authorized_token<'a>(
        &'a self,
        request: PreAuthorizedTokenRequest,
    ) -> CredentialIssuerFuture<'a, Result<PreAuthorizedTokenResponse, CredentialHttpError>> {
        self.pre_authorized_token_operation(request)
    }

    fn create_offer<'a>(
        &'a self,
        request: CreateCredentialOfferRequest,
    ) -> CredentialIssuerFuture<'a, Result<CreateCredentialOfferResponse, CredentialHttpError>>
    {
        self.create_offer_operation(request)
    }
}
#[cfg(test)]
#[path = "../../../../tests/unit/domain/openid4vci_endpoint_operations.rs"]
mod tests;
