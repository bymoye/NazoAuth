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
    PresentationService, PresentationStorePort, PresentationTransaction, RequestMethod,
    ResponseMode,
};
use nazo_runtime_modules::ModuleId;
use serde_json::json;
use uuid::Uuid;

use crate::{
    adapters::security::random_urlsafe_token, domain::Openid4vcCredentialCrypto,
    runtime_modules::ServerRuntimeModuleRegistry,
};

pub(crate) struct ServerPresentationOperations {
    store: nazo_postgres::Openid4vpRepository,
    conformance: nazo_postgres::ConformanceLeaseRepository,
    service: PresentationService<nazo_postgres::Openid4vpRepository, Openid4vcCredentialCrypto>,
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
            conformance: nazo_postgres::ConformanceLeaseRepository::new(pool),
            service,
            crypto,
            runtime,
            issuer: config.issuer,
            wallet_origins: config.wallet_origins,
            transaction_ttl_seconds: config.transaction_ttl_seconds.max(30),
            tenant_id,
        }
    }
    fn enabled(&self, admission: nazo_auth::CapabilityAdmission) -> bool {
        nazo_auth::module_admissible(
            &self.runtime.snapshot(),
            ModuleId::Openid4vpVerifier,
            admission,
        )
    }
    fn wallet_allowed(&self, endpoint: &str) -> bool {
        url::Url::parse(endpoint).ok().is_some_and(|url| {
            url.scheme() == "https"
                && self
                    .wallet_origins
                    .iter()
                    .any(|origin| url.origin().ascii_serialization() == *origin)
        })
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

    async fn conformance_lease_for_wallet(
        &self,
        wallet_authorization_endpoint: &str,
    ) -> Result<Option<Uuid>, PresentationHttpError> {
        let wallet_origin = url::Url::parse(wallet_authorization_endpoint)
            .map(|url| url.origin().ascii_serialization())
            .map_err(|_| {
                vp_error(
                    400,
                    "invalid_request",
                    "Wallet authorization endpoint is invalid.",
                )
            })?;
        let materials = self
            .conformance
            .active_public_materials_for_profile(self.tenant_id, "openid4vc")
            .await
            .map_err(|_| {
                vp_error(
                    503,
                    "server_error",
                    "Conformance trust state is unavailable.",
                )
            })?;
        let mut matches = Vec::new();
        for entry in materials {
            let material: nazo_operator_protocol::Openid4vcConformanceTrust =
                serde_json::from_value(entry.public_material).map_err(|_| {
                    vp_error(503, "server_error", "Conformance trust state is invalid.")
                })?;
            let issuer_origin = url::Url::parse(&material.client_attestation_issuer)
                .map(|url| url.origin().ascii_serialization())
                .map_err(|_| {
                    vp_error(503, "server_error", "Conformance trust state is invalid.")
                })?;
            if issuer_origin == wallet_origin {
                matches.push(entry.lease_id);
            }
        }
        match matches.as_slice() {
            [] => Ok(None),
            [lease_id] => Ok(Some(*lease_id)),
            _ => Err(vp_error(
                503,
                "server_error",
                "Conformance trust state is ambiguous.",
            )),
        }
    }

    async fn conformance_credential_trust_anchors(
        &self,
        lease_id: Option<Uuid>,
    ) -> Result<Vec<Vec<u8>>, PresentationHttpError> {
        let Some(lease_id) = lease_id else {
            return Ok(Vec::new());
        };
        let material = self
            .conformance
            .active_public_material_for_lease(self.tenant_id, lease_id)
            .await
            .map_err(|_| {
                vp_error(
                    503,
                    "server_error",
                    "Conformance trust state is unavailable.",
                )
            })?
            .ok_or_else(|| {
                vp_error(
                    400,
                    "invalid_request",
                    "Presentation transaction is invalid.",
                )
            })?;
        let material: nazo_operator_protocol::Openid4vcConformanceTrust =
            serde_json::from_value(material).map_err(|_| {
                vp_error(503, "server_error", "Conformance trust state is invalid.")
            })?;
        crate::domain::parse_conformance_credential_trust_anchor(
            &material.credential_trust_anchor_pem,
        )
        .map(|anchor| vec![anchor])
        .map_err(|_| {
            vp_error(
                503,
                "server_error",
                "Conformance credential trust anchor is invalid.",
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
            if !self.wallet_allowed(&input.wallet_authorization_endpoint) {
                return Err(vp_error(
                    400,
                    "invalid_request",
                    "Wallet authorization endpoint is not allowlisted.",
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
            let conformance_lease_id = self
                .conformance_lease_for_wallet(&input.wallet_authorization_endpoint)
                .await?;
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
                conformance_lease_id,
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
            let mut url = url::Url::parse(&input.wallet_authorization_endpoint).map_err(|_| {
                vp_error(
                    400,
                    "invalid_request",
                    "Wallet authorization endpoint is invalid.",
                )
            })?;
            if let Some(request_uri) = request_uri {
                url.query_pairs_mut()
                    .append_pair("client_id", &client_id)
                    .append_pair("request_uri", &request_uri);
                if matches!(method, RequestMethod::RequestUriSignedPost) {
                    url.query_pairs_mut()
                        .append_pair("request_uri_method", "post");
                }
            } else {
                let encoded = serde_json::to_value(&request).map_err(|_| {
                    vp_error(500, "server_error", "Presentation request encoding failed.")
                })?;
                for (name, value) in encoded.as_object().into_iter().flatten() {
                    url.query_pairs_mut()
                        .append_pair(name, value.as_str().unwrap_or(&value.to_string()));
                }
            }
            Ok(CreatePresentationResponse {
                transaction_id: id,
                authorization_url: url.into(),
                expires_in: self.transaction_ttl_seconds,
            })
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
            let additional_trust_anchors = self
                .conformance_credential_trust_anchors(transaction.conformance_lease_id)
                .await?;
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
