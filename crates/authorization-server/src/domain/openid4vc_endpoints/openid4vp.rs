use super::helpers::*;

use std::sync::Arc;

use base64::Engine as _;
use chrono::{Duration, Utc};
use nazo_digital_credentials::EphemeralEncryptionKey;
use nazo_openid4vc_http_actix::{
    CreatePresentationRequest, CreatePresentationResponse, PresentationFuture,
    PresentationHttpError, PresentationOperations, PresentationResponseBody,
    PresentationResponseInput,
};
use nazo_openid4vp::{
    AuthorizationRequest, AuthorizationResponse, ClientIdPrefix, ClientMetadata,
    PresentationCreateIdempotency, PresentationCreateOutcome, PresentationService,
    PresentationStoreError, PresentationStorePort, PresentationTransaction, RequestMethod,
    ResponseMode,
};
use nazo_persistence::{Openid4vcTrustPolicyRecord, Openid4vcTrustPolicyStore, Openid4vpStore};
use nazo_runtime_modules::ModuleId;
use serde_json::json;
use uuid::Uuid;

use crate::{
    adapters::security::random_urlsafe_token, domain::Openid4vcCredentialCrypto,
    runtime_modules::ServerRuntimeModuleRegistry,
};

pub(crate) struct ServerPresentationOperations {
    store: Arc<dyn Openid4vpStore>,
    trust_policies: Arc<dyn Openid4vcTrustPolicyStore>,
    service: PresentationService<Arc<dyn Openid4vpStore>, Openid4vcCredentialCrypto>,
    crypto: Openid4vcCredentialCrypto,
    runtime: Arc<ServerRuntimeModuleRegistry>,
    issuer: String,
    wallet_origins: Vec<String>,
    transaction_ttl_seconds: u64,
    tenant_id: Uuid,
}

pub(crate) struct PresentationVerifierConfig {
    pub(crate) issuer: String,
    pub(crate) wallet_origins: Vec<String>,
    pub(crate) transaction_ttl_seconds: u64,
}

impl ServerPresentationOperations {
    pub(crate) fn new(
        store: Arc<dyn Openid4vpStore>,
        tenant_id: Uuid,
        crypto: Openid4vcCredentialCrypto,
        runtime: Arc<ServerRuntimeModuleRegistry>,
        trust_policies: Arc<dyn Openid4vcTrustPolicyStore>,
        config: PresentationVerifierConfig,
    ) -> Self {
        let service = PresentationService::new(store.clone(), crypto.clone());
        Self {
            store,
            trust_policies,
            service,
            crypto,
            runtime,
            issuer: config.issuer,
            wallet_origins: config.wallet_origins,
            transaction_ttl_seconds: config.transaction_ttl_seconds.max(30),
            tenant_id,
        }
    }

    fn create_response(
        &self,
        transaction: &PresentationTransaction,
        create_request_jti: &str,
        create_request_sha256: &str,
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
            idempotency: nazo_operator_protocol::Openid4vpCreateIdempotencyBinding {
                create_request_jti: create_request_jti.to_owned(),
                create_request_sha256: create_request_sha256.to_owned(),
            },
            transaction_id: transaction.id,
            authorization_url: url.into(),
            expires_in: transaction
                .expires_at
                .signed_duration_since(transaction.created_at)
                .num_seconds()
                .max(0) as u64,
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
    ) -> Result<Option<Openid4vcTrustPolicyRecord>, PresentationHttpError> {
        let policy = self
            .trust_policies
            .active_for_origin(self.tenant_id, resource_id, wallet_origin, digest)
            .await
            .map_err(|_| {
                vp_error(
                    503,
                    "server_error",
                    "OpenID4VC trust policy state is unavailable.",
                )
            })?;
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
        crate::domain::parse_scoped_credential_trust_anchors(
            &policy.material.credential_trust_anchor_pem,
        )
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
            nazo_operator_protocol::validate_openid4vp_create_request_jti(
                &input.create_request_jti,
            )
            .map_err(|_| {
                vp_error(
                    400,
                    "invalid_request",
                    "create_request_jti must be a canonical lowercase UUID.",
                )
            })?;
            let wallet_origin = Self::wallet_origin(&input.wallet_authorization_endpoint)?;
            let wallet_authorization_endpoint =
                url::Url::parse(&input.wallet_authorization_endpoint)
                    .map_err(|_| {
                        vp_error(
                            400,
                            "invalid_request",
                            "Wallet authorization endpoint is invalid.",
                        )
                    })?
                    .to_string();
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
            if binding.is_none() && !static_wallet_allowed {
                return Err(vp_error(
                    400,
                    "invalid_request",
                    "The wallet origin is not statically trusted and no OpenID4VC trust policy was selected.",
                ));
            }
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
            let fixed_client_id = match prefix {
                ClientIdPrefix::RedirectUri => None,
                ClientIdPrefix::X509Hash => Some(self.crypto.x509_hash_client_id()),
                ClientIdPrefix::X509SanDns => {
                    Some(self.crypto.x509_san_dns_client_id().map_err(|_| {
                        vp_error(
                            400,
                            "invalid_request",
                            "x509_san_dns is unavailable for the verifier certificate.",
                        )
                    })?)
                }
            };
            let normalized_request = nazo_operator_protocol::Openid4vpNormalizedCreateRequest {
                wallet_authorization_endpoint: wallet_authorization_endpoint.clone(),
                dcql_query: serde_json::to_value(&input.dcql_query).map_err(|_| {
                    vp_error(400, "invalid_request", "DCQL query is not JSON encodable.")
                })?,
                haip: input.haip,
                client_id_prefix: prefix.as_str().to_owned(),
                request_method: method.as_str().to_owned(),
                response_mode: mode.as_str().to_owned(),
                transaction_data: input.transaction_data.clone(),
                openid4vc_trust_policy_resource_id: input
                    .openid4vc_trust_policy_resource_id
                    .clone(),
                openid4vc_trust_policy_digest: input.openid4vc_trust_policy_digest.clone(),
            };
            let (canonical_request, request_sha256) =
                nazo_operator_protocol::canonical_openid4vp_normalized_create_request(
                    &normalized_request,
                )
                .map_err(|_| {
                    vp_error(
                        400,
                        "invalid_request",
                        "Presentation create request cannot be normalized.",
                    )
                })?;
            if canonical_request.len()
                > nazo_operator_protocol::MAX_OPENID4VP_NORMALIZED_CREATE_REQUEST_BYTES
            {
                return Err(vp_error(
                    413,
                    "invalid_request",
                    "Presentation create request is too large.",
                ));
            }
            let idempotency = PresentationCreateIdempotency {
                request_jti: &input.create_request_jti,
                request_sha256: &request_sha256,
                canonical_request: &canonical_request,
            };
            match self.store.find_by_create_request(idempotency).await {
                Ok(Some(existing)) => {
                    return self.create_response(
                        &existing,
                        &input.create_request_jti,
                        &request_sha256,
                    );
                }
                Ok(None) => {}
                Err(PresentationStoreError::IdempotencyConflict) => {
                    return Err(vp_error(
                        409,
                        "conflict",
                        "create_request_jti is already bound to a different request.",
                    ));
                }
                Err(
                    PresentationStoreError::Unavailable | PresentationStoreError::InvalidTransition,
                ) => {
                    return Err(vp_error(
                        503,
                        "server_error",
                        "Presentation transaction state is unavailable.",
                    ));
                }
            }
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
            } else {
                debug_assert!(static_wallet_allowed);
                None
            };
            let id = Uuid::now_v7();
            let response_uri = format!("{}/openid4vp/response/{id}", self.issuer);
            let client_id = match prefix {
                ClientIdPrefix::RedirectUri => format!("redirect_uri:{response_uri}"),
                ClientIdPrefix::X509Hash | ClientIdPrefix::X509SanDns => fixed_client_id
                    .ok_or_else(|| {
                        vp_error(
                            503,
                            "server_error",
                            "Verifier client identity is unavailable.",
                        )
                    })?,
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
                wallet_authorization_endpoint,
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
            match self.store.create(&transaction, idempotency).await {
                Ok(PresentationCreateOutcome::Created) => {
                    self.create_response(&transaction, &input.create_request_jti, &request_sha256)
                }
                Ok(PresentationCreateOutcome::Existing(existing)) => {
                    self.create_response(&existing, &input.create_request_jti, &request_sha256)
                }
                Err(PresentationStoreError::IdempotencyConflict) => Err(vp_error(
                    409,
                    "conflict",
                    "create_request_jti is already bound to a different request.",
                )),
                Err(
                    PresentationStoreError::Unavailable | PresentationStoreError::InvalidTransition,
                ) => Err(vp_error(
                    503,
                    "server_error",
                    "Presentation transaction state is unavailable.",
                )),
            }
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
            self.service
                .verify_response(
                    &transaction,
                    &response,
                    &additional_trust_anchors,
                    Utc::now(),
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
}

#[cfg(test)]
#[path = "../../../tests/unit/domain/openid4vc_endpoints_openid4vp.rs"]
mod tests;
