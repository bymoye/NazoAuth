use super::helpers::*;

use std::sync::Arc;

use base64::Engine as _;
use chrono::{Duration, SecondsFormat, Utc};
use nazo_digital_credentials::EphemeralEncryptionKey;
use nazo_openid4vc_http_actix::{
    CreatePresentationRequest, CreatePresentationResponse, PresentationFuture,
    PresentationHttpError, PresentationOperations, PresentationResponseBody,
    PresentationResponseInput, PresentationVerificationProjection,
    PresentationVerificationResponse,
};
use nazo_openid4vp::{
    AuthorizationRequest, AuthorizationResponse, ClientIdPrefix, ClientMetadata,
    PresentationService, PresentationStorePort, PresentationTransaction, RequestMethod,
    ResponseMode,
};
use nazo_runtime_modules::ModuleId;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{
    adapters::security::random_urlsafe_token, domain::Openid4vcCredentialCrypto,
    runtime_modules::ServerRuntimeModuleRegistry,
};

pub(crate) struct ServerPresentationOperations {
    store: nazo_postgres::Openid4vpRepository,
    trust_policies: nazo_postgres::TenantResourceRepository,
    service: PresentationService<nazo_postgres::Openid4vpRepository, Openid4vcCredentialCrypto>,
    crypto: Openid4vcCredentialCrypto,
    runtime: Arc<ServerRuntimeModuleRegistry>,
    issuer: String,
    wallet_origins: Vec<String>,
    transaction_ttl_seconds: u64,
    tenant_id: Uuid,
    verification_signer: Option<Arc<crate::control_discovery::ControlDiscoveryEndpoint>>,
}

pub(crate) struct PresentationVerifierConfig {
    pub(crate) issuer: String,
    pub(crate) wallet_origins: Vec<String>,
    pub(crate) transaction_ttl_seconds: u64,
}

impl ServerPresentationOperations {
    const VERIFICATION_RECEIPT_TTL_SECONDS: i64 = 600;

    pub(crate) fn new(
        pool: nazo_postgres::DbPool,
        tenant_id: Uuid,
        data_key: [u8; 32],
        crypto: Openid4vcCredentialCrypto,
        runtime: Arc<ServerRuntimeModuleRegistry>,
        config: PresentationVerifierConfig,
    ) -> Self {
        let store = nazo_postgres::Openid4vpRepository::new(pool.clone(), tenant_id, data_key);
        let service = PresentationService::new(store.clone(), crypto.clone());
        Self {
            store,
            trust_policies: nazo_postgres::TenantResourceRepository::new(pool),
            service,
            crypto,
            runtime,
            issuer: config.issuer,
            wallet_origins: config.wallet_origins,
            transaction_ttl_seconds: config.transaction_ttl_seconds.max(30),
            tenant_id,
            verification_signer: None,
        }
    }

    pub(crate) fn with_verification_signer(
        mut self,
        signer: Arc<crate::control_discovery::ControlDiscoveryEndpoint>,
    ) -> Self {
        self.verification_signer = Some(signer);
        self
    }

    fn verification_intent_audience(&self) -> String {
        format!("{}/openid4vp/verification-intents", self.issuer)
    }

    fn verification_receipt_audience(&self) -> String {
        format!("{}/openid4vp/verification-receipts", self.issuer)
    }

    fn presentation_binding(
        transaction: &PresentationTransaction,
    ) -> Result<nazo_operator_protocol::Openid4vpPresentationBinding, PresentationHttpError> {
        let mut normalized_request = transaction.request.clone();
        normalized_request.wallet_nonce = None;
        let request_object_sha256 = transaction
            .request_object
            .as_deref()
            .map(nazo_operator_protocol::compact_sha256);
        let encoded = serde_json::to_vec(&json!({
            "client_id_prefix": transaction.client_id_prefix.as_str(),
            "request_method": transaction.request_method.as_str(),
            "response_mode": transaction.response_mode.as_str(),
            "wallet_authorization_endpoint": &transaction.wallet_authorization_endpoint,
            "authorization_request": normalized_request,
            "request_object_sha256": request_object_sha256,
            "request_uri": transaction.request_uri.as_deref(),
        }))
        .map_err(|_| {
            vp_error(
                503,
                "server_error",
                "Presentation request binding is unavailable.",
            )
        })?;
        let presentation_request_sha256 = format!("{:x}", Sha256::digest(encoded));
        let binding = nazo_operator_protocol::Openid4vpPresentationBinding {
            presentation_request_sha256,
            trust_policy: nazo_operator_protocol::Openid4vpTrustPolicyBinding {
                binding_id: transaction
                    .openid4vc_trust_policy_binding_id
                    .map(|value| value.to_string()),
                resource_id: transaction.openid4vc_trust_policy_resource_id.clone(),
                resource_digest: transaction.openid4vc_trust_policy_digest.clone(),
            },
        };
        nazo_operator_protocol::canonical_openid4vp_presentation_binding_sha256(&binding).map_err(
            |_| {
                vp_error(
                    503,
                    "server_error",
                    "Presentation request binding is invalid.",
                )
            },
        )?;
        Ok(binding)
    }

    fn attachment_response(
        attachment: &nazo_postgres::StoredOpenid4vpVerificationAttachment,
    ) -> Result<nazo_operator_protocol::Openid4vpAttachEvidenceResponse, PresentationHttpError>
    {
        let presentation_binding_sha256 =
            nazo_operator_protocol::canonical_openid4vp_presentation_binding_sha256(
                &attachment.presentation_binding,
            )
            .map_err(|_| {
                vp_error(
                    503,
                    "server_error",
                    "Presentation request binding is invalid.",
                )
            })?;
        Ok(nazo_operator_protocol::Openid4vpAttachEvidenceResponse {
            schema: 1,
            transaction_id: attachment.transaction_id.to_string(),
            status: nazo_operator_protocol::Openid4vpEvidenceAttachmentStatus::Attached,
            evidence_context_sha256: attachment.context_sha256.clone(),
            presentation_binding: attachment.presentation_binding.clone(),
            presentation_binding_sha256,
            intent_jws: attachment.intent_jws.clone(),
            intent_sha256: nazo_operator_protocol::compact_sha256(&attachment.intent_jws),
        })
    }

    fn create_response(
        &self,
        transaction: &PresentationTransaction,
    ) -> Result<CreatePresentationResponse, PresentationHttpError> {
        let mut url =
            url::Url::parse(&transaction.wallet_authorization_endpoint).map_err(|_| {
                vp_error(
                    400,
                    "invalid_request",
                    "Wallet authorization endpoint is invalid.",
                )
            })?;
        if let Some(request_uri) = transaction.request_uri.as_deref() {
            url.query_pairs_mut()
                .append_pair("client_id", &transaction.request.client_id)
                .append_pair("request_uri", request_uri);
            if matches!(
                transaction.request_method,
                RequestMethod::RequestUriSignedPost
            ) {
                url.query_pairs_mut()
                    .append_pair("request_uri_method", "post");
            }
        } else {
            let encoded = serde_json::to_value(&transaction.request).map_err(|_| {
                vp_error(500, "server_error", "Presentation request encoding failed.")
            })?;
            for (name, value) in encoded.as_object().into_iter().flatten() {
                url.query_pairs_mut()
                    .append_pair(name, value.as_str().unwrap_or(&value.to_string()));
            }
        }
        Ok(CreatePresentationResponse {
            transaction_id: transaction.id,
            authorization_url: url.into(),
            expires_in: transaction
                .expires_at
                .signed_duration_since(transaction.created_at)
                .num_seconds()
                .max(0) as u64,
        })
    }

    fn verify_intent(
        &self,
        compact: &str,
        transaction_id: Uuid,
        context_sha256: &str,
        presentation_binding_sha256: &str,
        now: i64,
    ) -> Result<nazo_operator_protocol::Openid4vpVerificationIntent, PresentationHttpError> {
        let signer = self.verification_signer.as_ref().ok_or_else(|| {
            vp_error(
                503,
                "server_error",
                "Presentation verification receipt signing is unavailable.",
            )
        })?;
        let audience = self.verification_intent_audience();
        let tenant_id = self.tenant_id.to_string();
        let transaction_id = transaction_id.to_string();
        nazo_operator_protocol::verify_openid4vp_verification_intent(
            compact,
            &nazo_operator_protocol::Openid4vpVerificationIntentExpectations {
                issuer: &self.issuer,
                audience: &audience,
                deployment_id: signer.deployment_id(),
                runtime_instance_id: signer.runtime_instance_id(),
                instance_key_id: signer.instance_key_id(),
                tenant_id: &tenant_id,
                transaction_id: &transaction_id,
                evidence_context_sha256: context_sha256,
                presentation_binding_sha256,
            },
            &signer.instance_verifying_key(),
            now,
        )
        .map_err(|_| {
            vp_error(
                503,
                "server_error",
                "Presentation verification intent is invalid.",
            )
        })
    }

    fn verified_projection(
        &self,
        evidence: &nazo_postgres::StoredOpenid4vpVerificationEvidence,
        now: i64,
    ) -> Result<PresentationVerificationProjection, PresentationHttpError> {
        let signer = self.verification_signer.as_ref().ok_or_else(|| {
            vp_error(
                503,
                "server_error",
                "Presentation verification receipt signing is unavailable.",
            )
        })?;
        let context_sha256 =
            nazo_operator_protocol::canonical_openid4vp_evidence_context_sha256(&evidence.context)
                .map_err(|_| {
                    vp_error(
                        503,
                        "server_error",
                        "Presentation verification context is invalid.",
                    )
                })?;
        let presentation_binding_sha256 =
            nazo_operator_protocol::canonical_openid4vp_presentation_binding_sha256(
                &evidence.presentation_binding,
            )
            .map_err(|_| {
                vp_error(
                    503,
                    "server_error",
                    "Presentation request binding is invalid.",
                )
            })?;
        let intent_sha256 = nazo_operator_protocol::compact_sha256(&evidence.intent_jws);
        let intent = self.verify_intent(
            &evidence.intent_jws,
            evidence.transaction_id,
            &context_sha256,
            &presentation_binding_sha256,
            evidence.completed_at.timestamp(),
        )?;
        let audience = self.verification_receipt_audience();
        let transaction_id = evidence.transaction_id.to_string();
        let receipt_id = evidence.receipt_id.to_string();
        let receipt = nazo_operator_protocol::verify_openid4vp_verification_receipt(
            &evidence.receipt_jws,
            &nazo_operator_protocol::Openid4vpVerificationReceiptExpectations {
                issuer: &self.issuer,
                audience: &audience,
                deployment_id: signer.deployment_id(),
                runtime_instance_id: signer.runtime_instance_id(),
                instance_key_id: signer.instance_key_id(),
                tenant_id: &self.tenant_id.to_string(),
                transaction_id: &transaction_id,
                receipt_id: &receipt_id,
                issuance_request_jti: &evidence.issuance_request_jti,
                evidence_context_sha256: &context_sha256,
                presentation_binding_sha256: &presentation_binding_sha256,
                intent_sha256: &intent_sha256,
                capability_sha256: &evidence.capability_sha256,
            },
            &signer.instance_verifying_key(),
            now,
        )
        .map_err(|_| {
            vp_error(
                503,
                "server_error",
                "Presentation verification receipt is invalid.",
            )
        })?;
        if receipt.evidence_context != intent.evidence_context
            || receipt.presentation_binding != intent.presentation_binding
            || receipt.presentation_binding != evidence.presentation_binding
            || receipt.iat != evidence.issued_at.timestamp()
            || receipt.exp != evidence.expires_at.timestamp()
            || receipt.completed_at
                != evidence
                    .completed_at
                    .to_rfc3339_opts(SecondsFormat::Secs, true)
        {
            return Err(vp_error(
                503,
                "server_error",
                "Presentation verification receipt binding is invalid.",
            ));
        }
        Ok(PresentationVerificationProjection {
            schema: receipt.schema,
            issuer: receipt.iss,
            deployment_id: receipt.deployment_id,
            runtime_instance_id: receipt.runtime_instance_id,
            instance_key_id: receipt.instance_key_id,
            tenant_id: receipt.tenant_id,
            receipt_id: receipt.jti,
            transaction_id: evidence.transaction_id,
            issuance_request_jti: receipt.issuance_request_jti,
            status: receipt.status,
            evidence_context: receipt.evidence_context,
            presentation_binding: receipt.presentation_binding,
            intent_sha256: receipt.intent_sha256,
            completed_at: receipt.completed_at,
            expires_at: evidence
                .expires_at
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            receipt_sha256: nazo_operator_protocol::compact_sha256(&evidence.receipt_jws),
        })
    }
    fn enabled(&self, admission: nazo_auth::CapabilityAdmission) -> bool {
        nazo_auth::module_admissible(
            &self.runtime.snapshot(),
            ModuleId::Openid4vpVerifier,
            admission,
        )
    }
    fn wallet_origin(endpoint: &str) -> Result<String, PresentationHttpError> {
        let url = url::Url::parse(endpoint).map_err(|_| {
            vp_error(
                400,
                "invalid_request",
                "Wallet authorization endpoint is invalid.",
            )
        })?;
        if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
            return Err(vp_error(
                400,
                "invalid_request",
                "Wallet authorization endpoint is invalid.",
            ));
        }
        Ok(url.origin().ascii_serialization())
    }

    fn static_wallet_origin_allowed(&self, origin: &str) -> bool {
        self.wallet_origins
            .iter()
            .any(|configured| configured == origin)
    }
    async fn request_object(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<String, PresentationHttpError> {
        let now = Utc::now().timestamp();
        let mut claims = serde_json::to_value(request)
            .map_err(|_| vp_error(500, "server_error", "Presentation request encoding failed."))?;
        claims["iss"] = json!(request.client_id);
        claims["aud"] = json!("https://self-issued.me/v2");
        claims["iat"] = json!(now);
        claims["exp"] = json!(now + self.transaction_ttl_seconds as i64);
        claims["jti"] = json!(Uuid::now_v7());
        self.crypto
            .sign_request_object(&claims)
            .await
            .map_err(|_| vp_error(503, "server_error", "Presentation request signing failed."))
    }

    async fn active_trust_policy(
        &self,
        resource_id: &str,
        wallet_origin: &str,
        digest: &str,
    ) -> Result<Option<nazo_postgres::StoredOpenid4vcTrustPolicy>, PresentationHttpError> {
        let mut connection = self.trust_policies.connection().await.map_err(|_| {
            vp_error(
                503,
                "server_error",
                "OpenID4VC trust policy state is unavailable.",
            )
        })?;
        let policy = nazo_postgres::TenantResourceRepository::active_openid4vc_trust_policy_for_origin_on_connection(
            &mut connection,
            self.tenant_id,
            resource_id,
            wallet_origin,
            digest,
        )
        .await
        .map_err(|_| {
            vp_error(
                503,
                "server_error",
                "OpenID4VC trust policy state is unavailable.",
            )
        })?;
        if let Some(policy) = &policy {
            let material: nazo_operator_protocol::Openid4vcTrustPolicy =
                serde_json::from_value(policy.public_material.clone()).map_err(|_| {
                    vp_error(503, "server_error", "OpenID4VC trust policy is invalid.")
                })?;
            nazo_operator_protocol::validate_openid4vc_trust_policy(&material)
                .map_err(|_| vp_error(503, "server_error", "OpenID4VC trust policy is invalid."))?;
        }
        Ok(policy)
    }

    async fn credential_trust_anchors(
        &self,
        transaction: &PresentationTransaction,
    ) -> Result<Vec<Vec<u8>>, PresentationHttpError> {
        let binding = match (
            transaction.openid4vc_trust_policy_binding_id,
            transaction.openid4vc_trust_policy_resource_id.as_deref(),
            transaction.openid4vc_trust_policy_digest.as_deref(),
        ) {
            (None, None, None) => return Ok(Vec::new()),
            (Some(binding_id), Some(resource_id), Some(digest)) => {
                (binding_id, resource_id, digest)
            }
            _ => {
                return Err(vp_error(
                    503,
                    "server_error",
                    "Presentation trust policy binding is invalid.",
                ));
            }
        };
        let wallet_origin = Self::wallet_origin(&transaction.wallet_authorization_endpoint)?;
        let policy = self
            .active_trust_policy(binding.1, &wallet_origin, binding.2)
            .await?
            .ok_or_else(|| {
                vp_error(
                    400,
                    "invalid_request",
                    "Presentation transaction is invalid.",
                )
            })?;
        if policy.id != binding.0 {
            return Err(vp_error(
                400,
                "invalid_request",
                "Presentation transaction is invalid.",
            ));
        }
        let material: nazo_operator_protocol::Openid4vcTrustPolicy =
            serde_json::from_value(policy.public_material)
                .map_err(|_| vp_error(503, "server_error", "OpenID4VC trust policy is invalid."))?;
        nazo_operator_protocol::validate_openid4vc_trust_policy(&material)
            .map_err(|_| vp_error(503, "server_error", "OpenID4VC trust policy is invalid."))?;
        crate::domain::parse_scoped_credential_trust_anchors(&material.credential_trust_anchor_pem)
            .map_err(|_| {
                vp_error(
                    503,
                    "server_error",
                    "OpenID4VC credential trust anchor is invalid.",
                )
            })
    }
}

impl PresentationOperations for ServerPresentationOperations {
    fn create<'a>(
        &'a self,
        input: CreatePresentationRequest,
    ) -> PresentationFuture<'a, Result<CreatePresentationResponse, PresentationHttpError>> {
        Box::pin(async move {
            if !self.enabled(nazo_auth::CapabilityAdmission::NewRequest) {
                return Err(vp_error(
                    503,
                    "temporarily_unavailable",
                    "Presentation verifier is unavailable.",
                ));
            }
            let wallet_origin = Self::wallet_origin(&input.wallet_authorization_endpoint)?;
            let static_wallet_allowed = self.static_wallet_origin_allowed(&wallet_origin);
            let binding = match (
                input.openid4vc_trust_policy_resource_id.as_deref(),
                input.openid4vc_trust_policy_digest.as_deref(),
            ) {
                (None, None) => None,
                (Some(resource_id), Some(digest)) => Some((resource_id, digest)),
                _ => {
                    return Err(vp_error(
                        400,
                        "invalid_request",
                        "OpenID4VC trust policy binding is incomplete.",
                    ));
                }
            };
            let trust_policy = if let Some((resource_id, digest)) = binding {
                Some(
                    self.active_trust_policy(resource_id, &wallet_origin, digest)
                        .await?
                        .ok_or_else(|| {
                            vp_error(
                                400,
                                "invalid_request",
                                "OpenID4VC trust policy binding is not active.",
                            )
                        })?,
                )
            } else if static_wallet_allowed {
                None
            } else {
                return Err(vp_error(
                    400,
                    "invalid_request",
                    "The wallet origin is not statically trusted and no active OpenID4VC trust policy was selected.",
                ));
            };
            input
                .dcql_query
                .validate()
                .map_err(|_| vp_error(400, "invalid_request", "DCQL query is invalid."))?;
            let prefix: ClientIdPrefix = input
                .client_id_prefix
                .as_deref()
                .unwrap_or("x509_hash")
                .parse()
                .map_err(|_| vp_error(400, "invalid_request", "client_id prefix is invalid."))?;
            let method: RequestMethod = input
                .request_method
                .as_deref()
                .unwrap_or("request_uri_signed_post")
                .parse()
                .map_err(|_| vp_error(400, "invalid_request", "request method is invalid."))?;
            let mode: ResponseMode = input
                .response_mode
                .as_deref()
                .unwrap_or(if input.haip {
                    "direct_post.jwt"
                } else {
                    "direct_post"
                })
                .parse()
                .map_err(|_| vp_error(400, "invalid_request", "response mode is invalid."))?;
            nazo_openid4vp::PresentationPolicy {
                client_id_prefix: prefix,
                request_method: method,
                response_mode: mode,
                haip: input.haip,
            }
            .validate()
            .map_err(|_| {
                vp_error(
                    400,
                    "invalid_request",
                    "Presentation security policy rejected this combination.",
                )
            })?;
            let id = Uuid::now_v7();
            let response_uri = format!("{}/openid4vp/response/{id}", self.issuer);
            let client_id = match prefix {
                ClientIdPrefix::RedirectUri => format!("redirect_uri:{response_uri}"),
                ClientIdPrefix::X509Hash => self.crypto.x509_hash_client_id(),
                ClientIdPrefix::X509SanDns => {
                    self.crypto.x509_san_dns_client_id().map_err(|_| {
                        vp_error(
                            500,
                            "server_error",
                            "Verifier certificate has no DNS identity.",
                        )
                    })?
                }
            };
            let response_key =
                (mode == ResponseMode::DirectPostJwt).then(EphemeralEncryptionKey::generate);
            let response_jwks = response_key.as_ref().map(|key| {
                let mut jwk = key.public_jwk();
                jwk["kid"] = json!(Uuid::now_v7().to_string());
                jwk["alg"] = json!("ECDH-ES");
                json!({"keys":[jwk]})
            });
            let transaction_data = input
                .transaction_data
                .map(|values| {
                    values
                        .into_iter()
                        .map(|value| {
                            serde_json::to_vec(&value)
                                .map(|encoded| {
                                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(encoded)
                                })
                                .map_err(|_| {
                                    vp_error(
                                        400,
                                        "invalid_request",
                                        "Transaction data is not JSON encodable.",
                                    )
                                })
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?;
            let request = AuthorizationRequest {
                client_id: client_id.clone(),
                response_type: "vp_token".to_owned(),
                response_mode: mode.as_str().to_owned(),
                response_uri: response_uri.clone(),
                nonce: random_urlsafe_token(),
                state: random_urlsafe_token(),
                dcql_query: input.dcql_query,
                client_metadata: Some(ClientMetadata {
                    vp_formats_supported: json!({"dc+sd-jwt":{"sd-jwt_alg_values":["ES256"],"kb-jwt_alg_values":["ES256"]},"mso_mdoc":{"issuerauth_alg_values":[-7],"deviceauth_alg_values":[-7]}}),
                    jwks: response_jwks,
                    encrypted_response_enc_values_supported: response_key
                        .as_ref()
                        .map(|_| vec!["A128GCM".to_owned(), "A256GCM".to_owned()]),
                }),
                verifier_info: None,
                transaction_data,
                wallet_nonce: None,
            };
            request.validate().map_err(|_| {
                vp_error(400, "invalid_request", "Presentation request is invalid.")
            })?;
            let request_uri = (!matches!(method, RequestMethod::UrlQuery))
                .then(|| format!("{}/openid4vp/request/{id}", self.issuer));
            let request_object = if matches!(method, RequestMethod::UrlQuery) {
                None
            } else {
                Some(self.request_object(&request).await?)
            };
            let now = Utc::now();
            let transaction = PresentationTransaction {
                id,
                client_id_prefix: prefix,
                request_method: method,
                response_mode: mode,
                wallet_authorization_endpoint: input.wallet_authorization_endpoint.clone(),
                request: request.clone(),
                request_object,
                request_uri: request_uri.clone(),
                openid4vc_trust_policy_binding_id: trust_policy.as_ref().map(|policy| policy.id),
                openid4vc_trust_policy_resource_id: trust_policy
                    .as_ref()
                    .map(|policy| policy.resource_id.clone()),
                openid4vc_trust_policy_digest: trust_policy
                    .as_ref()
                    .map(|policy| policy.resource_digest.clone()),
                response_encryption_private_key: response_key
                    .map(|key| key.secret_bytes().to_vec()),
                created_at: now,
                expires_at: now + Duration::seconds(self.transaction_ttl_seconds as i64),
            };
            self.store.create(&transaction).await.map_err(|_| {
                vp_error(
                    503,
                    "server_error",
                    "Presentation transaction state is unavailable.",
                )
            })?;
            self.create_response(&transaction)
        })
    }

    fn request<'a>(
        &'a self,
        transaction_id: Uuid,
        wallet_nonce: Option<&'a str>,
    ) -> PresentationFuture<'a, Result<PresentationResponseBody, PresentationHttpError>> {
        Box::pin(async move {
            let mut transaction = self
                .store
                .request(transaction_id, Utc::now())
                .await
                .map_err(|_| {
                    vp_error(
                        503,
                        "server_error",
                        "Presentation transaction state is unavailable.",
                    )
                })?
                .ok_or_else(|| {
                    vp_error(
                        404,
                        "invalid_request_uri",
                        "Presentation request URI is invalid.",
                    )
                })?;
            if matches!(
                transaction.request_method,
                RequestMethod::RequestUriSignedPost
            ) {
                let nonce = wallet_nonce
                    .filter(|nonce| !nonce.is_empty())
                    .ok_or_else(|| {
                        vp_error(
                            400,
                            "invalid_request",
                            "wallet_nonce is required for POST request_uri retrieval.",
                        )
                    })?;
                transaction = self
                    .store
                    .bind_wallet_nonce(transaction_id, nonce, Utc::now())
                    .await
                    .map_err(|_| {
                        vp_error(
                            503,
                            "server_error",
                            "Presentation transaction state is unavailable.",
                        )
                    })?
                    .ok_or_else(|| {
                        vp_error(
                            404,
                            "invalid_request_uri",
                            "Presentation request URI is invalid.",
                        )
                    })?;
                return self
                    .request_object(&transaction.request)
                    .await
                    .map(PresentationResponseBody::RequestObject);
            }
            transaction
                .request_object
                .map(PresentationResponseBody::RequestObject)
                .ok_or_else(|| {
                    vp_error(
                        404,
                        "invalid_request_uri",
                        "Presentation request object is unavailable.",
                    )
                })
        })
    }

    fn respond<'a>(
        &'a self,
        transaction_id: Uuid,
        input: PresentationResponseInput,
    ) -> PresentationFuture<'a, Result<Option<String>, PresentationHttpError>> {
        Box::pin(async move {
            let transaction = self
                .store
                .request(transaction_id, Utc::now())
                .await
                .map_err(|_| {
                    vp_error(
                        503,
                        "server_error",
                        "Presentation transaction state is unavailable.",
                    )
                })?
                .ok_or_else(|| {
                    vp_error(
                        400,
                        "invalid_request",
                        "Presentation transaction is invalid.",
                    )
                })?;
            let response: AuthorizationResponse = match input {
                PresentationResponseInput::DirectPost(response)
                    if transaction.response_mode == ResponseMode::DirectPost =>
                {
                    response
                }
                PresentationResponseInput::DirectPostJwt(encoded)
                    if transaction.response_mode == ResponseMode::DirectPostJwt =>
                {
                    let key: [u8; 32] = transaction
                        .response_encryption_private_key
                        .as_deref()
                        .and_then(|value| value.try_into().ok())
                        .ok_or_else(|| {
                            vp_error(
                                503,
                                "server_error",
                                "Presentation response key is unavailable.",
                            )
                        })?;
                    let plaintext = EphemeralEncryptionKey::from_secret_bytes(&key)
                        .and_then(|key| key.decrypt(&encoded))
                        .map_err(|_| {
                            vp_error(
                                400,
                                "invalid_request",
                                "Encrypted presentation response is invalid.",
                            )
                        })?;
                    serde_json::from_slice(&plaintext).map_err(|_| {
                        vp_error(
                            400,
                            "invalid_request",
                            "Encrypted presentation response is malformed.",
                        )
                    })?
                }
                _ => {
                    return Err(vp_error(
                        400,
                        "invalid_request",
                        "Presentation response mode does not match the transaction.",
                    ));
                }
            };
            let additional_trust_anchors = self.credential_trust_anchors(&transaction).await?;
            let now = Utc::now();
            let verification_attachment = self
                .store
                .verification_attachment_for_completion(transaction_id, now)
                .await
                .map_err(|_| {
                    vp_error(
                        503,
                        "server_error",
                        "Presentation verification intent state is unavailable.",
                    )
                })?;
            let current_presentation_binding = Self::presentation_binding(&transaction)?;
            let verification_binding = if let Some(attachment) = verification_attachment.as_ref() {
                let presentation_binding_sha256 =
                    nazo_operator_protocol::canonical_openid4vp_presentation_binding_sha256(
                        &current_presentation_binding,
                    )
                    .map_err(|_| {
                        vp_error(
                            503,
                            "server_error",
                            "Presentation request binding is invalid.",
                        )
                    })?;
                let intent = self.verify_intent(
                    &attachment.intent_jws,
                    transaction_id,
                    &attachment.context_sha256,
                    &presentation_binding_sha256,
                    now.timestamp(),
                )?;
                if intent.evidence_context != attachment.context
                    || intent.presentation_binding != current_presentation_binding
                    || attachment.presentation_binding != current_presentation_binding
                {
                    return Err(vp_error(
                        503,
                        "server_error",
                        "Presentation verification intent binding is invalid.",
                    ));
                }
                Some(nazo_openid4vp::PresentationCompletionBinding {
                    context_sha256: &attachment.context_sha256,
                    intent_jws: &attachment.intent_jws,
                    presentation_request_sha256: &current_presentation_binding
                        .presentation_request_sha256,
                    trust_policy_binding_id: transaction.openid4vc_trust_policy_binding_id,
                    trust_policy_resource_id: transaction
                        .openid4vc_trust_policy_resource_id
                        .as_deref(),
                    trust_policy_digest: transaction.openid4vc_trust_policy_digest.as_deref(),
                })
            } else {
                None
            };
            self.service
                .verify_response(
                    &transaction,
                    &response,
                    &additional_trust_anchors,
                    verification_binding,
                    now,
                )
                .await
                .map_err(|error| {
                    tracing::warn!(
                        %transaction_id,
                        %error,
                        "OpenID4VP presentation verification rejected a response"
                    );
                    vp_error(400, "invalid_request", "Presentation verification failed.")
                })?;
            Ok(Some(format!(
                "{}/openid4vp/complete/{transaction_id}",
                self.issuer
            )))
        })
    }

    fn result<'a>(
        &'a self,
        transaction_id: Uuid,
    ) -> PresentationFuture<'a, Result<nazo_openid4vp::PresentationResult, PresentationHttpError>>
    {
        Box::pin(async move {
            self.store
                .result(transaction_id, Utc::now())
                .await
                .map_err(|_| {
                    vp_error(
                        503,
                        "server_error",
                        "Presentation result state is unavailable.",
                    )
                })?
                .and_then(|stored| stored.completed)
                .ok_or_else(|| vp_error(404, "not_found", "Presentation result is not available."))
        })
    }

    fn attach_verification_evidence<'a>(
        &'a self,
        transaction_id: Uuid,
        request: nazo_operator_protocol::Openid4vpAttachEvidenceRequest,
    ) -> PresentationFuture<
        'a,
        Result<nazo_operator_protocol::Openid4vpAttachEvidenceResponse, PresentationHttpError>,
    > {
        Box::pin(async move {
            if request.schema != 1 {
                return Err(vp_error(
                    400,
                    "invalid_request",
                    "Unsupported presentation evidence attachment schema.",
                ));
            }
            let now = Utc::now();
            let context_sha256 =
                nazo_operator_protocol::canonical_openid4vp_evidence_context_sha256(
                    &request.evidence_context,
                )
                .map_err(|_| {
                    vp_error(
                        400,
                        "invalid_request",
                        "Presentation evidence context is invalid.",
                    )
                })?;
            let transaction = self
                .store
                .request(transaction_id, now)
                .await
                .map_err(|_| {
                    vp_error(
                        503,
                        "server_error",
                        "Presentation transaction state is unavailable.",
                    )
                })?
                .ok_or_else(|| {
                    vp_error(
                        404,
                        "not_found",
                        "Presentation transaction is not available for evidence attachment.",
                    )
                })?;
            let presentation_binding = Self::presentation_binding(&transaction)?;
            let presentation_binding_sha256 =
                nazo_operator_protocol::canonical_openid4vp_presentation_binding_sha256(
                    &presentation_binding,
                )
                .map_err(|_| {
                    vp_error(
                        503,
                        "server_error",
                        "Presentation request binding is invalid.",
                    )
                })?;
            let state = self
                .store
                .verification_attachment_state(transaction_id, now)
                .await
                .map_err(|_| {
                    vp_error(
                        503,
                        "server_error",
                        "Presentation evidence attachment state is unavailable.",
                    )
                })?
                .ok_or_else(|| {
                    vp_error(
                        404,
                        "not_found",
                        "Presentation transaction is not available for evidence attachment.",
                    )
                })?;
            let attachment = match state {
                nazo_postgres::Openid4vpVerificationAttachmentState::Pending {
                    expires_at, ..
                } => {
                    let signer = self.verification_signer.as_ref().ok_or_else(|| {
                        vp_error(
                            503,
                            "server_error",
                            "Presentation verification receipt signing is unavailable.",
                        )
                    })?;
                    let intent_expires_at = std::cmp::min(
                        expires_at,
                        now + Duration::seconds(Self::VERIFICATION_RECEIPT_TTL_SECONDS),
                    );
                    if intent_expires_at <= now {
                        return Err(vp_error(
                            404,
                            "not_found",
                            "Presentation transaction is not available for evidence attachment.",
                        ));
                    }
                    let intent = nazo_operator_protocol::Openid4vpVerificationIntent {
                        schema: 1,
                        iss: self.issuer.clone(),
                        aud: self.verification_intent_audience(),
                        jti: transaction_id.to_string(),
                        iat: now.timestamp(),
                        exp: intent_expires_at.timestamp(),
                        deployment_id: signer.deployment_id().to_owned(),
                        runtime_instance_id: signer.runtime_instance_id().to_owned(),
                        instance_key_id: signer.instance_key_id().to_owned(),
                        tenant_id: self.tenant_id.to_string(),
                        transaction_id: transaction_id.to_string(),
                        evidence_context: request.evidence_context.clone(),
                        presentation_binding: presentation_binding.clone(),
                    };
                    let intent_jws =
                        signer
                            .sign_openid4vp_verification_intent(&intent)
                            .map_err(|_| {
                                vp_error(
                                    503,
                                    "server_error",
                                    "Presentation verification intent signing failed.",
                                )
                            })?;
                    self.store
                        .attach_verification_evidence(
                            transaction_id,
                            nazo_postgres::NewOpenid4vpVerificationAttachment {
                                context: &request.evidence_context,
                                context_sha256: &context_sha256,
                                intent_jws: &intent_jws,
                                presentation_request_sha256: &presentation_binding
                                    .presentation_request_sha256,
                            },
                            now,
                        )
                        .await
                        .map_err(|error| match error {
                            nazo_openid4vp::PresentationStoreError::InvalidTransition => vp_error(
                                409,
                                "conflict",
                                "Presentation evidence context is already bound or terminal.",
                            ),
                            nazo_openid4vp::PresentationStoreError::Unavailable => vp_error(
                                503,
                                "server_error",
                                "Presentation evidence attachment state is unavailable.",
                            ),
                        })?
                        .ok_or_else(|| {
                            vp_error(
                                404,
                                "not_found",
                                "Presentation transaction is not available for evidence attachment.",
                            )
                        })?
                }
                nazo_postgres::Openid4vpVerificationAttachmentState::Attached(attachment)
                    if attachment.context == request.evidence_context
                        && attachment.context_sha256 == context_sha256 =>
                {
                    attachment
                }
                _ => {
                    return Err(vp_error(
                        409,
                        "conflict",
                        "Presentation evidence context is already bound or terminal.",
                    ));
                }
            };
            let intent = self.verify_intent(
                &attachment.intent_jws,
                transaction_id,
                &attachment.context_sha256,
                &presentation_binding_sha256,
                now.timestamp(),
            )?;
            if intent.evidence_context != attachment.context
                || intent.presentation_binding != attachment.presentation_binding
            {
                return Err(vp_error(
                    503,
                    "server_error",
                    "Presentation verification intent binding is invalid.",
                ));
            }
            Self::attachment_response(&attachment)
        })
    }

    fn issue_verification_receipt<'a>(
        &'a self,
        transaction_id: Uuid,
        request: nazo_operator_protocol::Openid4vpIssueVerificationReceiptRequest,
    ) -> PresentationFuture<'a, Result<PresentationVerificationResponse, PresentationHttpError>>
    {
        Box::pin(async move {
            if request.schema != 1
                || !matches!(
                    Uuid::parse_str(&request.issuance_request_jti),
                    Ok(value) if value.to_string() == request.issuance_request_jti
                )
            {
                return Err(vp_error(
                    400,
                    "invalid_request",
                    "Presentation verification issuance request is invalid.",
                ));
            }
            let now = Utc::now();
            let prepared = self
                .store
                .prepare_verification_evidence(transaction_id, now)
                .await
                .map_err(|_| {
                    vp_error(
                        503,
                        "server_error",
                        "Presentation verification receipt state is unavailable.",
                    )
                })?
                .ok_or_else(|| {
                    vp_error(
                        404,
                        "not_found",
                        "Presentation verification receipt is not available.",
                    )
                })?;
            let presentation_binding_sha256 =
                nazo_operator_protocol::canonical_openid4vp_presentation_binding_sha256(
                    &prepared.presentation_binding,
                )
                .map_err(|_| {
                    vp_error(
                        503,
                        "server_error",
                        "Presentation request binding is invalid.",
                    )
                })?;
            let intent = self.verify_intent(
                &prepared.intent_jws,
                prepared.transaction_id,
                &prepared.context_sha256,
                &presentation_binding_sha256,
                prepared.completed_at.timestamp(),
            )?;
            if intent.evidence_context != prepared.context
                || intent.presentation_binding != prepared.presentation_binding
            {
                return Err(vp_error(
                    503,
                    "server_error",
                    "Presentation verification intent binding is invalid.",
                ));
            }
            let issued_at = chrono::DateTime::<Utc>::from_timestamp(now.timestamp(), 0)
                .ok_or_else(|| {
                    vp_error(
                        503,
                        "server_error",
                        "Presentation verification issuance time is invalid.",
                    )
                })?;
            let expires_at = issued_at + Duration::seconds(Self::VERIFICATION_RECEIPT_TTL_SECONDS);
            if expires_at <= issued_at {
                return Err(vp_error(
                    404,
                    "not_found",
                    "Presentation verification receipt is not available.",
                ));
            }
            let capability = random_urlsafe_token();
            let capability_sha256 =
                nazo_operator_protocol::openid4vp_verification_capability_sha256(&capability)
                    .map_err(|_| {
                        vp_error(
                            503,
                            "server_error",
                            "Presentation verification capability generation failed.",
                        )
                    })?;
            let receipt_id = Uuid::now_v7();
            let signer = self.verification_signer.as_ref().ok_or_else(|| {
                vp_error(
                    503,
                    "server_error",
                    "Presentation verification receipt signing is unavailable.",
                )
            })?;
            let receipt = nazo_operator_protocol::Openid4vpVerificationReceipt {
                schema: 1,
                iss: self.issuer.clone(),
                aud: self.verification_receipt_audience(),
                jti: receipt_id.to_string(),
                iat: issued_at.timestamp(),
                exp: expires_at.timestamp(),
                deployment_id: signer.deployment_id().to_owned(),
                runtime_instance_id: signer.runtime_instance_id().to_owned(),
                instance_key_id: signer.instance_key_id().to_owned(),
                tenant_id: self.tenant_id.to_string(),
                transaction_id: transaction_id.to_string(),
                issuance_request_jti: request.issuance_request_jti.clone(),
                status: nazo_operator_protocol::Openid4vpVerificationStatus::Verified,
                evidence_context: intent.evidence_context,
                presentation_binding: intent.presentation_binding,
                intent_sha256: nazo_operator_protocol::compact_sha256(&prepared.intent_jws),
                completed_at: prepared
                    .completed_at
                    .to_rfc3339_opts(SecondsFormat::Secs, true),
                capability_sha256: capability_sha256.clone(),
            };
            let receipt_jws = signer
                .sign_openid4vp_verification_receipt(&receipt)
                .map_err(|_| {
                    vp_error(
                        503,
                        "server_error",
                        "Presentation verification receipt signing failed.",
                    )
                })?;
            let evidence = self
                .store
                .issue_verification_evidence(
                    transaction_id,
                    receipt_id,
                    &request.issuance_request_jti,
                    &capability,
                    &capability_sha256,
                    &receipt_jws,
                    &prepared.intent_jws,
                    &prepared.context_sha256,
                    &prepared.presentation_binding,
                    issued_at,
                    expires_at,
                )
                .await
                .map_err(|error| match error {
                    nazo_openid4vp::PresentationStoreError::InvalidTransition => vp_error(
                        409,
                        "conflict",
                        "Presentation verification issuance request conflicts with prior state.",
                    ),
                    nazo_openid4vp::PresentationStoreError::Unavailable => vp_error(
                        503,
                        "server_error",
                        "Presentation verification receipt state is unavailable.",
                    ),
                })?
                .ok_or_else(|| {
                    vp_error(
                        404,
                        "not_found",
                        "Presentation verification receipt is not available.",
                    )
                })?;
            let projection = self.verified_projection(&evidence.evidence, issued_at.timestamp())?;
            Ok(PresentationVerificationResponse {
                projection,
                receipt_jws: evidence.evidence.receipt_jws,
                receipt_api_url: self.verification_receipt_audience(),
                verification_ui_url: format!(
                    "{}/ui/verification-result#receipt={}",
                    self.issuer, evidence.capability
                ),
                verification_ttl_seconds: evidence
                    .evidence
                    .expires_at
                    .signed_duration_since(evidence.evidence.issued_at)
                    .num_seconds()
                    .max(0) as u64,
            })
        })
    }

    fn verification_receipt<'a>(
        &'a self,
        capability: &'a str,
    ) -> PresentationFuture<'a, Result<PresentationVerificationProjection, PresentationHttpError>>
    {
        Box::pin(async move {
            let now = Utc::now();
            let capability_sha256 =
                nazo_operator_protocol::openid4vp_verification_capability_sha256(capability)
                    .map_err(|_| {
                        vp_error(
                            404,
                            "not_found",
                            "Presentation verification receipt is not available.",
                        )
                    })?;
            let evidence = self
                .store
                .verification_evidence_by_capability_sha256(&capability_sha256, now)
                .await
                .map_err(|_| {
                    vp_error(
                        503,
                        "server_error",
                        "Presentation verification receipt state is unavailable.",
                    )
                })?
                .ok_or_else(|| {
                    vp_error(
                        404,
                        "not_found",
                        "Presentation verification receipt is not available.",
                    )
                })?;
            self.verified_projection(&evidence, now.timestamp())
        })
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/domain/openid4vc_endpoints_openid4vp.rs"]
mod tests;
