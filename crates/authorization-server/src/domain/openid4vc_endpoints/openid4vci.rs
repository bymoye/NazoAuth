use super::helpers::*;

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::Arc,
};

use base64::Engine as _;
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
    CredentialDatasetPort, CredentialIssuance, CredentialIssuerMetadata, CredentialIssuerService,
    CredentialOffer, CredentialOfferGrants, CredentialRequest, CredentialRequestEncryptionMetadata,
    CredentialResponse, CredentialResponseEncryption, CredentialStorePort,
    DeferredCredentialRequest, DeferredPayload, EncryptionMetadata, IssuanceDisposition,
    IssuanceNotification, NonceRecord, NotificationRequest, PreAuthorizedCodeGrant,
    TxCodeDescription,
};
use nazo_runtime_modules::ModuleId;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    adapters::security::{blake3_hex, hash_password_blocking_limited, random_urlsafe_token},
    domain::{
        Openid4vcClientAttestationValidator, Openid4vcCredentialCrypto, Openid4vcProofValidator,
    },
    http::{authorization::ServerAuthorizationService, token::ServerTokenService},
    runtime_modules::ServerRuntimeModuleRegistry,
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

const VCI_CREDENTIAL_IDENTIFIER_PREFIX: &str = "nazo-vci-";

pub(crate) fn openid4vci_authorization_detail(
    issuer: &str,
    credential_configuration_id: &str,
) -> Value {
    json!({
        "type": "openid_credential",
        "credential_configuration_id": credential_configuration_id,
        "credential_identifiers": [
            openid4vci_credential_identifier(credential_configuration_id).0
        ],
        "locations": [issuer],
    })
}

pub(crate) fn openid4vci_credential_identifier(
    credential_configuration_id: &str,
) -> nazo_openid4vci::CredentialIdentifier {
    nazo_openid4vci::CredentialIdentifier(format!(
        "{VCI_CREDENTIAL_IDENTIFIER_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential_configuration_id)
    ))
}

pub(crate) fn openid4vci_configuration_id_from_identifier(
    identifier: &nazo_openid4vci::CredentialIdentifier,
) -> Option<String> {
    let encoded = identifier
        .0
        .strip_prefix(VCI_CREDENTIAL_IDENTIFIER_PREFIX)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()?;
    String::from_utf8(decoded).ok()
}

pub(crate) fn token_endpoint_dpop_target_uris(issuer: &str, request_url: &str) -> Vec<String> {
    let public = format!("{}/token", issuer.trim_end_matches('/'));
    let trusted_request_url = url::Url::parse(request_url).ok().and_then(|request| {
        let issuer = url::Url::parse(issuer).ok()?;
        (request.scheme() == issuer.scheme()
            && request.host_str() == issuer.host_str()
            && request.port_or_known_default() == issuer.port_or_known_default()
            && request.path() == "/token")
            .then(|| request_url.to_owned())
    });
    [Some(public), trusted_request_url]
        .into_iter()
        .flatten()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[derive(Clone)]
struct Openid4vcDataset {
    store: nazo_postgres::Openid4vciDatasetRepository,
}

impl CredentialDatasetPort for Openid4vcDataset {
    fn dataset<'a>(
        &'a self,
        access: &'a CredentialAccess,
        configuration_id: &'a str,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Value, nazo_openid4vci::CredentialIssuanceError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.store
                .dataset(access.tenant_id, access.subject_id, configuration_id)
                .await
                .map_err(|_| nazo_openid4vci::CredentialIssuanceError::DatasetUnavailable)?
                .ok_or(nazo_openid4vci::CredentialIssuanceError::DatasetUnavailable)
        })
    }
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
        let dpop_jkt = claims.cnf.as_ref().and_then(|cnf| cnf.jkt.clone());
        match (
            dpop_jkt.as_deref(),
            context.access_token_scheme,
            context.dpop_proof.as_deref(),
        ) {
            (Some(_), AccessTokenScheme::Dpop, Some(_)) => {}
            (None, AccessTokenScheme::Bearer, None) => {}
            (Some(_), _, _) => {
                return Err(vci_error(
                    401,
                    "invalid_token",
                    "A DPoP-bound access token requires the DPoP authorization scheme and proof.",
                ));
            }
            (None, _, _) => {
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
        Box::pin(async move {
            if !self.enabled(nazo_auth::CapabilityAdmission::ExistingTransaction) {
                return Err(vci_error(
                    404,
                    "invalid_request",
                    "Credential issuer is disabled.",
                ));
            }
            let id = Uuid::parse_str(offer_id).map_err(|_| {
                vci_error(404, "invalid_request", "Credential offer was not found.")
            })?;
            let stored = self
                .store
                .offer(id, Utc::now())
                .await
                .map_err(|_| {
                    vci_error(
                        503,
                        "server_error",
                        "Credential offer state is unavailable.",
                    )
                })?
                .ok_or_else(|| {
                    vci_error(404, "invalid_request", "Credential offer was not found.")
                })?;
            Ok(CredentialOffer {
                credential_issuer: self.issuer.clone(),
                credential_configuration_ids: stored.credential_configuration_ids,
                grants: Some(stored.grants),
            })
        })
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
        Box::pin(async move {
            if !self.enabled(nazo_auth::CapabilityAdmission::NewRequest) {
                return Err(vci_error(
                    503,
                    "temporarily_unavailable",
                    "Credential issuer is not accepting new requests.",
                ));
            }
            let request = self.request_json(body).await?;
            let access = self.access(&context).await?;
            let request_digest = issuance_request_digest(
                "credential",
                &request,
                &context.request_url,
                context.method,
            )?;
            let issuance_id = stable_issuance_id(access.token_id, &request_digest);
            if let Some(response) = self
                .store
                .find_response(issuance_id, access.token_id, &request_digest, Utc::now())
                .await
                .map_err(|_| {
                    vci_error(
                        503,
                        "server_error",
                        "Credential issuance response state is unavailable.",
                    )
                })?
            {
                return response_from_record(response);
            }
            let dpop_nonce = self.next_dpop_nonce(&access).await?;
            let configuration_id = resolve_configuration_id(&request, &access)?;
            let configuration = self
                .configurations
                .get(&configuration_id)
                .cloned()
                .ok_or_else(|| {
                    vci_error(
                        400,
                        "unknown_credential_configuration",
                        "Credential configuration is unknown.",
                    )
                })?;
            let nonce = extract_proof_nonce(request.proofs.as_ref())
                .ok_or_else(|| vci_error(400, "invalid_proof", "Credential proof is missing."))?;
            let now = Utc::now();
            let disposition = if self.deferred_configurations.contains(&configuration_id) {
                IssuanceDisposition::Deferred {
                    ready_at: now + Duration::seconds(1),
                }
            } else {
                IssuanceDisposition::Immediate
            };
            let pending = self
                .service
                .issue_pending_with_identity(
                    &access,
                    &request,
                    &CredentialIssuance {
                        configuration_id,
                        configuration,
                        disposition,
                        status: None,
                        expires_at: now + Duration::days(365),
                    },
                    &nonce,
                    nazo_openid4vci::IssuanceIdentity {
                        issuance_id,
                        request_digest: request_digest.clone(),
                    },
                    now,
                )
                .await
                .map_err(map_issuance_error)?;
            let body = match self
                .finish_response(
                    pending.response.clone(),
                    request.credential_response_encryption.as_ref(),
                )
                .await
            {
                Ok(body) => body,
                Err(error) => {
                    let _ = self.service.rollback_pending(&pending, Utc::now()).await;
                    return Err(error);
                }
            };
            let response_record = stored_response(
                issuance_id,
                access.token_id,
                request_digest,
                &body,
                dpop_nonce.clone(),
                access.expires_at,
            )?;
            if let Err(error) = self
                .service
                .commit_pending_with_response(&pending, &response_record, Utc::now())
                .await
            {
                let _ = self.service.rollback_pending(&pending, Utc::now()).await;
                return Err(map_issuance_error(error));
            }
            Ok(CredentialEndpointResponse { body, dpop_nonce })
        })
    }

    fn deferred<'a>(
        &'a self,
        context: CredentialRequestContext,
        body: CredentialRequestBody<DeferredCredentialRequest>,
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        Box::pin(async move {
            if !self.enabled(nazo_auth::CapabilityAdmission::ExistingTransaction) {
                return Err(vci_error(
                    503,
                    "temporarily_unavailable",
                    "Credential issuer is unavailable.",
                ));
            }
            let request = self.request_json(body).await?;
            let access = self.access(&context).await?;
            let request_digest = issuance_request_digest(
                "deferred",
                &request,
                &context.request_url,
                context.method,
            )?;
            let issuance_id = stable_issuance_id(access.token_id, &request_digest);
            if let Some(response) = self
                .store
                .find_response(issuance_id, access.token_id, &request_digest, Utc::now())
                .await
                .map_err(|_| {
                    vci_error(
                        503,
                        "server_error",
                        "Credential issuance response state is unavailable.",
                    )
                })?
            {
                return response_from_record(response);
            }
            let dpop_nonce = self.next_dpop_nonce(&access).await?;
            let transaction_hash = blake3_hex(&request.transaction_id);
            let claim_id = Uuid::now_v7().to_string();
            let deferred = self
                .store
                .claim_ready_deferred(&transaction_hash, access.token_id, &claim_id, Utc::now())
                .await
                .map_err(|_| {
                    vci_error(
                        503,
                        "server_error",
                        "Deferred credential state is unavailable.",
                    )
                })?
                .ok_or_else(|| {
                    vci_error(
                        400,
                        "invalid_transaction_id",
                        "Deferred credential transaction is invalid or not ready.",
                    )
                })?
                .credential;
            let result = async {
                let payload: DeferredPayload = serde_json::from_slice(&deferred.payload_ciphertext)
                    .map_err(|_| {
                        vci_error(
                            503,
                            "server_error",
                            "Deferred credential payload is unavailable.",
                        )
                    })?;
                let configuration = self
                    .configurations
                    .get(&deferred.configuration_id)
                    .ok_or_else(|| {
                        vci_error(
                            503,
                            "server_error",
                            "Deferred credential configuration is unavailable.",
                        )
                    })?;
                let mut credentials = Vec::new();
                for holder_binding in deferred.holder_bindings {
                    let credential = self
                        .crypto
                        .sign(&nazo_digital_credentials::CredentialSignInput {
                            payload: nazo_digital_credentials::CredentialPayload {
                                issuer: self.issuer.clone(),
                                format: deferred.format,
                                configuration_id: deferred.configuration_id.clone(),
                                credential_type: configuration
                                    .vct
                                    .clone()
                                    .or_else(|| configuration.doctype.clone())
                                    .ok_or_else(|| {
                                        vci_error(
                                            503,
                                            "server_error",
                                            "Deferred credential type is unavailable.",
                                        )
                                    })?,
                                subject_claims: payload.dataset.clone(),
                                holder_binding: serde_json::from_value(holder_binding).ok(),
                                selectively_disclosable_claims: Vec::new(),
                            },
                            issued_at: payload.issued_at,
                            expires_at: payload.expires_at,
                            status: payload.status.clone(),
                        })
                        .await
                        .map_err(|_| {
                            vci_error(503, "server_error", "Deferred credential signing failed.")
                        })?;
                    credentials.push(nazo_openid4vci::IssuedCredential {
                        credential: Value::String(credential),
                    });
                }
                let notification_id = Uuid::now_v7().to_string();
                let notification_handle = nazo_openid4vci::NotificationHandle {
                    notification_id: notification_id.clone(),
                    token_id: access.token_id,
                    expires_at: access.expires_at.min(payload.expires_at),
                };
                // Finish response encoding before committing the lease. If
                // encryption fails, the transaction remains retryable.
                let body = self
                    .finish_response(
                        CredentialResponse {
                            credentials: Some(credentials),
                            transaction_id: None,
                            notification_id: Some(notification_id),
                            interval: None,
                        },
                        request.credential_response_encryption.as_ref(),
                    )
                    .await?;
                let response_record = stored_response(
                    issuance_id,
                    access.token_id,
                    request_digest.clone(),
                    &body,
                    dpop_nonce.clone(),
                    access.expires_at.min(payload.expires_at),
                )?;
                let committed = self
                    .store
                    .finalize_deferred_with_notification_and_response(
                        &transaction_hash,
                        access.token_id,
                        &claim_id,
                        &notification_handle,
                        &response_record,
                        Utc::now(),
                    )
                    .await
                    .map_err(|_| {
                        vci_error(
                            503,
                            "server_error",
                            "Deferred credential state is unavailable.",
                        )
                    })?;
                if !committed {
                    return Err(vci_error(
                        503,
                        "server_error",
                        "Deferred credential state transition was lost.",
                    ));
                }
                Ok(CredentialEndpointResponse { body, dpop_nonce })
            }
            .await;
            if result.is_err() {
                let _ = self
                    .store
                    .release_deferred(&transaction_hash, access.token_id, &claim_id, Utc::now())
                    .await;
            }
            result
        })
    }

    fn notify<'a>(
        &'a self,
        context: CredentialRequestContext,
        request: NotificationRequest,
    ) -> CredentialIssuerFuture<'a, Result<CredentialEndpointResponse<()>, CredentialHttpError>>
    {
        Box::pin(async move {
            let access = self.access(&context).await?;
            let dpop_nonce = self.next_dpop_nonce(&access).await?;
            let recorded = self
                .store
                .record_notification(&IssuanceNotification {
                    notification_id: request.notification_id,
                    token_id: access.token_id,
                    event: request.event,
                    description: request.event_description,
                    occurred_at: Utc::now(),
                })
                .await
                .map_err(|_| {
                    vci_error(503, "server_error", "Notification state is unavailable.")
                })?;
            if !recorded {
                return Err(vci_error(
                    400,
                    "invalid_notification_id",
                    "Notification identifier is invalid or already terminal.",
                ));
            }
            Ok(CredentialEndpointResponse {
                body: (),
                dpop_nonce,
            })
        })
    }

    fn pre_authorized_token<'a>(
        &'a self,
        request: PreAuthorizedTokenRequest,
    ) -> CredentialIssuerFuture<'a, Result<PreAuthorizedTokenResponse, CredentialHttpError>> {
        Box::pin(async move {
            if !self.enabled(nazo_auth::CapabilityAdmission::NewRequest) {
                return Err(vci_error(
                    503,
                    "temporarily_unavailable",
                    "Credential issuer is unavailable.",
                ));
            }
            let target_uris = token_endpoint_dpop_target_uris(&self.issuer, &request.request_url);
            let target_uri_refs = target_uris.iter().map(String::as_str).collect::<Vec<_>>();
            let dpop_jkt = validate_authorization_server_dpop(
                self.authorization.as_ref(),
                DpopProofRequest {
                    proof: request.dpop_proof.as_deref(),
                    method: "POST",
                    target_uris: &target_uri_refs,
                    access_token: None,
                    expected_jkt: None,
                },
                self.dpop_nonce_policy,
            )
            .await
            .map_err(|error| match error {
                DpopError::UseNonce(nonce) => CredentialHttpError {
                    status: 400,
                    error: "use_dpop_nonce",
                    description: "Credential issuer requires nonce in DPoP proof.",
                    dpop_nonce: Some(nonce),
                },
                DpopError::NonceStoreUnavailable => {
                    vci_error(503, "server_error", "DPoP nonce validation is unavailable.")
                }
                _ => vci_error(400, "invalid_dpop_proof", "DPoP proof is invalid."),
            })?;
            let attested = match (
                request.client_attestation.as_deref(),
                request.client_attestation_pop.as_deref(),
            ) {
                (None, None) => None,
                (Some(attestation), Some(proof)) => {
                    let validator = self.client_attestation.as_ref().ok_or_else(|| {
                        vci_error(
                            401,
                            "invalid_client_attestation",
                            "Client attestation is not configured.",
                        )
                    })?;
                    let validated = validator
                        .validate_for_client(
                            attestation,
                            proof,
                            &self.issuer,
                            Utc::now().timestamp(),
                        )
                        .await
                        .map_err(|_| {
                            vci_error(
                                401,
                                "invalid_client_attestation",
                                "Client attestation is invalid.",
                            )
                        })?;
                    if request
                        .client_id
                        .as_deref()
                        .is_some_and(|client_id| client_id != validated.client_id)
                    {
                        return Err(vci_error(
                            401,
                            "invalid_client_attestation",
                            "Client identity does not match the attestation.",
                        ));
                    }
                    let replay_key = format!("client-attestation:{}", validated.client_id);
                    let fresh = self
                        .authorization
                        .consume_private_key_jwt(
                            &replay_key,
                            &validated.replay_id,
                            validated.replay_ttl_seconds,
                        )
                        .await
                        .map_err(|_| {
                            vci_error(
                                503,
                                "server_error",
                                "Client attestation replay state is unavailable.",
                            )
                        })?;
                    if !fresh {
                        return Err(vci_error(
                            401,
                            "invalid_client_attestation",
                            "Client attestation proof was replayed.",
                        ));
                    }
                    Some(validated)
                }
                _ => {
                    return Err(vci_error(
                        400,
                        "invalid_request",
                        "Both client attestation headers are required.",
                    ));
                }
            };
            let client_id = attested
                .as_ref()
                .map(|attestation| attestation.client_id.as_str())
                .or(request.client_id.as_deref())
                .unwrap_or("pre-authorized-wallet");
            let authorization = self
                .store
                .consume_pre_authorized_offer(
                    &blake3_hex(&request.pre_authorized_code),
                    request.tx_code.as_deref(),
                    client_id,
                    Utc::now(),
                )
                .await
                .map_err(|_| {
                    vci_error(
                        503,
                        "server_error",
                        "Credential offer state is unavailable.",
                    )
                })?
                .ok_or_else(|| {
                    vci_error(
                        400,
                        "invalid_grant",
                        "Pre-authorized code or transaction code is invalid.",
                    )
                })?;
            let authorization_details = authorization
                .configuration_ids
                .iter()
                .map(|id| openid4vci_authorization_detail(&self.issuer, id))
                .collect::<Vec<_>>();
            let issued = self
                .token_service
                .sign_access_token(nazo_auth::AccessTokenSignInput {
                    issuer: &self.issuer,
                    tenant_id: authorization.tenant_id,
                    subject: &authorization.subject_id.to_string(),
                    user_id: Some(authorization.subject_id),
                    subject_type: "user",
                    client_id,
                    audiences: std::slice::from_ref(&self.issuer),
                    scopes: &[],
                    authorization_details: &Value::Array(authorization_details.clone()),
                    userinfo_claims: &[],
                    userinfo_claim_requests: &[],
                    ttl_seconds: (authorization.expires_at - Utc::now()).num_seconds().max(1),
                    dpop_jkt: dpop_jkt.as_deref(),
                    mtls_x5t_s256: None,
                    actor: None,
                })
                .await
                .map_err(|_| {
                    vci_error(
                        503,
                        "server_error",
                        "Credential access token signing failed.",
                    )
                })?;
            // The pre-authorized offer is consumed before the JWT is signed.  Persist the
            // resulting grant before returning the bearer/DPoP token so every token delivered
            // by this endpoint is visible to the credential endpoint's revocation and
            // lifecycle checks.  A failed persistence write fails closed: the token is never
            // sent to the wallet.
            let token_id = Uuid::parse_str(&issued.jti).map_err(|_| {
                vci_error(
                    503,
                    "server_error",
                    "Credential access token identifier is invalid.",
                )
            })?;
            let expires_at =
                chrono::DateTime::from_timestamp(issued.expires_at, 0).ok_or_else(|| {
                    vci_error(
                        503,
                        "server_error",
                        "Credential access token expiry is invalid.",
                    )
                })?;
            self.store
                .upsert_access(
                    &blake3_hex(&issued.token),
                    &CredentialAccess {
                        token_id,
                        tenant_id: authorization.tenant_id,
                        subject_id: authorization.subject_id,
                        client_id: client_id.to_owned(),
                        configuration_ids: authorization.configuration_ids.clone(),
                        credential_identifiers: authorization.credential_identifiers.clone(),
                        dpop_jkt: dpop_jkt.clone(),
                        expires_at,
                    },
                )
                .await
                .map_err(|_| {
                    vci_error(
                        503,
                        "server_error",
                        "Credential access state is unavailable.",
                    )
                })?;
            Ok(PreAuthorizedTokenResponse {
                access_token: issued.token,
                token_type: if dpop_jkt.is_some() { "DPoP" } else { "Bearer" }.to_owned(),
                expires_in: (issued.expires_at - Utc::now().timestamp()).max(1) as u64,
                authorization_details,
            })
        })
    }

    fn create_offer<'a>(
        &'a self,
        request: CreateCredentialOfferRequest,
    ) -> CredentialIssuerFuture<'a, Result<CreateCredentialOfferResponse, CredentialHttpError>>
    {
        Box::pin(async move {
            if !self.enabled(nazo_auth::CapabilityAdmission::NewRequest) {
                return Err(vci_error(
                    503,
                    "temporarily_unavailable",
                    "Credential issuer is unavailable.",
                ));
            }
            if request.credential_configuration_ids.is_empty()
                || request.credential_configuration_ids.len() > 16
                || !request
                    .credential_configuration_ids
                    .iter()
                    .all(|id| self.configurations.contains_key(id))
            {
                return Err(vci_error(
                    400,
                    "invalid_request",
                    "Credential offer configurations are invalid.",
                ));
            }
            let grant_types = request
                .grant_types
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            if grant_types.is_empty()
                || grant_types.len() != request.grant_types.len()
                || !grant_types.iter().all(|grant| {
                    matches!(
                        *grant,
                        "authorization_code" | nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT
                    )
                })
                || request.tx_code.is_some()
                    && !grant_types.contains(nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT)
            {
                return Err(vci_error(
                    400,
                    "invalid_request",
                    "Credential offer grant types are invalid.",
                ));
            }
            let tenant = TenantId::new(self.tenant_id)
                .map_err(|_| vci_error(500, "server_error", "Credential tenant is invalid."))?;
            let subject = UserId::new(request.subject_id)
                .map_err(|_| vci_error(400, "invalid_request", "Credential subject is invalid."))?;
            if !self
                .users
                .is_active_by_tenant_id(tenant, subject)
                .await
                .map_err(|_| vci_error(503, "server_error", "Credential subject lookup failed."))?
            {
                return Err(vci_error(
                    400,
                    "invalid_request",
                    "Credential subject is not active.",
                ));
            }
            for configuration_id in &request.credential_configuration_ids {
                let available = self
                    .datasets
                    .dataset(self.tenant_id, request.subject_id, configuration_id)
                    .await
                    .map_err(|_| {
                        vci_error(503, "server_error", "Credential dataset lookup failed.")
                    })?
                    .is_some();
                if !available {
                    return Err(vci_error(
                        400,
                        "invalid_request",
                        "Requested credential data is unavailable for the subject.",
                    ));
                }
            }
            if !(30..=600).contains(&request.expires_in) {
                return Err(vci_error(
                    400,
                    "invalid_request",
                    "Credential offer lifetime must be between 30 and 600 seconds.",
                ));
            }
            if request.tx_code.as_ref().is_some_and(|code| {
                !(4..=32).contains(&code.len()) || code.chars().any(char::is_whitespace)
            }) {
                return Err(vci_error(
                    400,
                    "invalid_request",
                    "Transaction code is invalid.",
                ));
            }

            let issuer_state = grant_types
                .contains("authorization_code")
                .then(random_urlsafe_token);
            let pre_authorized_code = grant_types
                .contains(nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT)
                .then(random_urlsafe_token);
            let grants = CredentialOfferGrants::new(
                issuer_state
                    .as_ref()
                    .map(|issuer_state| AuthorizationCodeGrant {
                        issuer_state: Some(issuer_state.clone()),
                        authorization_server: Some(self.issuer.clone()),
                    }),
                pre_authorized_code
                    .as_ref()
                    .map(|pre_authorized_code| PreAuthorizedCodeGrant {
                        pre_authorized_code: pre_authorized_code.clone(),
                        tx_code: request.tx_code.as_ref().map(|code| TxCodeDescription {
                            input_mode: Some(
                                if code.chars().all(|value| value.is_ascii_digit()) {
                                    "numeric"
                                } else {
                                    "text"
                                }
                                .to_owned(),
                            ),
                            length: Some(code.len() as u16),
                            description: None,
                        }),
                        authorization_server: Some(self.issuer.clone()),
                    }),
            );
            let id = Uuid::now_v7();
            let offer = nazo_openid4vci::StoredCredentialOffer {
                id,
                tenant_id: self.tenant_id,
                subject_id: Some(request.subject_id),
                credential_configuration_ids: request.credential_configuration_ids,
                grants: grants.clone(),
                expires_at: Utc::now() + Duration::seconds(request.expires_in as i64),
            };
            let tx_code_hash = match request.tx_code {
                Some(code) => Some(hash_password_blocking_limited(code).await.map_err(|_| {
                    vci_error(
                        503,
                        "server_error",
                        "Transaction code hashing is unavailable.",
                    )
                })?),
                None => None,
            };
            let issuer_state_hash = issuer_state.as_deref().map(blake3_hex);
            let pre_authorized_code_hash = pre_authorized_code.as_deref().map(blake3_hex);
            self.store
                .insert_offer(
                    &offer,
                    issuer_state_hash.as_deref(),
                    pre_authorized_code_hash.as_deref(),
                    tx_code_hash.as_deref(),
                )
                .await
                .map_err(|_| {
                    vci_error(503, "server_error", "Credential offer persistence failed.")
                })?;
            let credential_offer_uri = format!("{}/openid4vci/offers/{id}", self.issuer);
            Ok(CreateCredentialOfferResponse {
                offer_id: id,
                credential_offer_uri,
                credential_offer: CredentialOffer {
                    credential_issuer: self.issuer.clone(),
                    credential_configuration_ids: offer.credential_configuration_ids,
                    grants: Some(grants),
                },
            })
        })
    }
}
