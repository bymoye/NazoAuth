use crate::http::client_ip::IpCidr;
use crate::settings::{DpopNoncePolicy, Settings};

#[derive(Clone)]
pub(crate) struct ResourceServerConfig {
    pub(crate) issuer: String,
    pub(crate) mtls_endpoint_base_url: String,
    pub(crate) default_audience: String,
    pub(crate) protected_resource_identifier: String,
    pub(crate) dpop_nonce_policy: DpopNoncePolicy,
    pub(crate) fapi_http_signature_max_age_seconds: i64,
    pub(crate) trusted_proxy_cidrs: Vec<IpCidr>,
}

impl From<&Settings> for ResourceServerConfig {
    fn from(settings: &Settings) -> Self {
        let endpoint = &settings.endpoint;
        let protocol = &settings.protocol;
        Self {
            issuer: endpoint.issuer.clone(),
            mtls_endpoint_base_url: endpoint.mtls_endpoint_base_url.clone(),
            default_audience: protocol.default_audience.to_owned(),
            protected_resource_identifier: protocol.protected_resource_identifier.to_owned(),
            dpop_nonce_policy: protocol.dpop_nonce_policy,
            fapi_http_signature_max_age_seconds: protocol.fapi_http_signature_max_age_seconds,
            trusted_proxy_cidrs: endpoint.trusted_proxy_cidrs.to_vec(),
        }
    }
}

mod production {
    use std::sync::{Arc, Mutex};

    use actix_web::HttpRequest;
    use jsonwebtoken::Algorithm;
    use nazo_http_actix::{
        FapiAuthorizationError, FapiFuture, FapiHttpMessageSignatures, FapiMtlsThumbprintResolver,
        FapiResourceAuthorizer, FapiResponseSignature, FapiSignatureOperationError,
        FapiSignatureVerificationError,
    };
    use nazo_http_signatures::VerifiedInput;
    use nazo_key_management::{HttpSigningLease, KeySnapshot};
    use nazo_resource_server::{
        ConfirmationPolicy, DpopNoncePolicy as ResourceDpopNoncePolicy, DpopProofVerifier,
        DpopProofVerifierConfig, ProtectedResourceAuthorizationContext,
        ProtectedResourceAuthorizationRequest, ProtectedResourceAuthorizationResult,
        ProtectedResourceAuthorizationService, ResourceServerVerifier,
        ResourceServerVerifierConfig,
    };
    use nazo_runtime_modules::ModuleId;

    use crate::{
        http::mtls::request_mtls_thumbprint_from_trusted_proxy,
        runtime_modules::ServerRuntimeModuleRegistry, settings::DpopNoncePolicy,
    };

    use super::ResourceServerConfig;

    type ServerResourceAuthorizationService = ProtectedResourceAuthorizationService<
        nazo_postgres::TokenRepository,
        nazo_valkey::ReplayStore,
    >;

    struct CachedResourceAuthorizationService {
        keys: Arc<KeySnapshot>,
        service: Arc<ServerResourceAuthorizationService>,
    }

    fn same_key_generation(cached: &Arc<KeySnapshot>, current: &Arc<KeySnapshot>) -> bool {
        // The cache entry strongly owns `cached`, so its allocation cannot be
        // freed or have its address reused while this comparison executes.
        Arc::ptr_eq(cached, current)
    }

    #[derive(Clone)]
    pub(crate) struct ServerFapiResourceAuthorizer {
        config: ResourceServerConfig,
        keyset: nazo_key_management::KeyManager,
        tokens: nazo_postgres::TokenRepository,
        replay: nazo_valkey::ReplayStore,
        service_cache: Arc<Mutex<Option<CachedResourceAuthorizationService>>>,
    }

    impl ServerFapiResourceAuthorizer {
        pub(crate) fn new(
            config: ResourceServerConfig,
            keyset: nazo_key_management::KeyManager,
            tokens: nazo_postgres::TokenRepository,
            replay: nazo_valkey::ReplayStore,
        ) -> Self {
            Self {
                config,
                keyset,
                tokens,
                replay,
                service_cache: Arc::new(Mutex::new(None)),
            }
        }

        fn service(
            &self,
        ) -> Result<Arc<ServerResourceAuthorizationService>, FapiAuthorizationError> {
            let keys = self.keyset.snapshot();
            let mut cache = self.service_cache.lock().map_err(|_| {
                FapiAuthorizationError::Protocol(
                    nazo_resource_server::ProtectedResourceAuthorizationError::InvalidToken(
                        nazo_resource_server::ResourceServerVerifierError::MissingJwks,
                    ),
                )
            })?;
            if let Some(cached) = cache.as_ref()
                && same_key_generation(&cached.keys, &keys)
            {
                return Ok(cached.service.clone());
            }
            let verifier = ResourceServerVerifier::new(ResourceServerVerifierConfig {
                issuer: self.config.issuer.clone(),
                audiences: vec![
                    self.config.default_audience.clone(),
                    self.config.protected_resource_identifier.clone(),
                ],
                jwks: keys.jwks(),
                required_scopes: Vec::new(),
                confirmation: ConfirmationPolicy::Optional,
                allowed_algs: vec![
                    Algorithm::EdDSA,
                    Algorithm::RS256,
                    Algorithm::ES256,
                    Algorithm::PS256,
                ],
                clock_skew_seconds: 0,
            })
            .map_err(|error| {
                FapiAuthorizationError::Protocol(
                    nazo_resource_server::ProtectedResourceAuthorizationError::InvalidToken(error),
                )
            })?;
            let service = Arc::new(
                ProtectedResourceAuthorizationService::new(
                    verifier,
                    DpopProofVerifier::new(DpopProofVerifierConfig {
                        allowed_algs: vec![Algorithm::EdDSA, Algorithm::ES256],
                        clock_skew_seconds: 30,
                        max_age_seconds: 300,
                        required_nonce: None,
                    }),
                    self.tokens.clone(),
                    self.replay.clone(),
                )
                .with_dpop_nonce_policy(match self.config.dpop_nonce_policy {
                    DpopNoncePolicy::Required => ResourceDpopNoncePolicy::Required,
                    DpopNoncePolicy::Optional => ResourceDpopNoncePolicy::Optional,
                }),
            );
            *cache = Some(CachedResourceAuthorizationService {
                keys,
                service: service.clone(),
            });
            Ok(service)
        }
    }

    impl FapiResourceAuthorizer for ServerFapiResourceAuthorizer {
        fn authorize<'a>(
            &'a self,
            request: ProtectedResourceAuthorizationRequest<'a>,
            context: ProtectedResourceAuthorizationContext<'a>,
        ) -> FapiFuture<'a, Result<ProtectedResourceAuthorizationResult, FapiAuthorizationError>>
        {
            Box::pin(async move {
                let service = self.service()?;
                let result = service
                    .authorize(request, context)
                    .await
                    .map_err(FapiAuthorizationError::Protocol)?;
                Ok(result)
            })
        }
    }

    #[derive(Clone)]
    pub(crate) struct ServerFapiMtlsResolver {
        trusted_proxy_cidrs: Arc<[crate::http::client_ip::IpCidr]>,
    }

    impl ServerFapiMtlsResolver {
        pub(crate) fn new(trusted_proxy_cidrs: Vec<crate::http::client_ip::IpCidr>) -> Self {
            Self {
                trusted_proxy_cidrs: trusted_proxy_cidrs.into(),
            }
        }
    }

    impl FapiMtlsThumbprintResolver for ServerFapiMtlsResolver {
        fn resolve(&self, request: &HttpRequest) -> Option<String> {
            request_mtls_thumbprint_from_trusted_proxy(request, &self.trusted_proxy_cidrs)
        }
    }

    #[derive(Clone)]
    pub(crate) struct ServerFapiHttpMessageSignatures {
        clients: nazo_postgres::OAuthClientRepository,
        replay: nazo_valkey::ReplayStore,
        keyset: nazo_key_management::KeyManager,
        runtime_modules: Arc<ServerRuntimeModuleRegistry>,
        max_age_seconds: i64,
    }

    impl ServerFapiHttpMessageSignatures {
        pub(crate) fn new(
            clients: nazo_postgres::OAuthClientRepository,
            replay: nazo_valkey::ReplayStore,
            keyset: nazo_key_management::KeyManager,
            runtime_modules: Arc<ServerRuntimeModuleRegistry>,
            max_age_seconds: i64,
        ) -> Self {
            Self {
                clients,
                replay,
                keyset,
                runtime_modules,
                max_age_seconds,
            }
        }
    }

    impl FapiHttpMessageSignatures for ServerFapiHttpMessageSignatures {
        fn enabled(&self) -> bool {
            nazo_auth::module_admissible(
                &self.runtime_modules.snapshot(),
                ModuleId::HttpMessageSignatures,
                nazo_auth::CapabilityAdmission::NewRequest,
            )
        }

        fn verify_and_consume<'a>(
            &'a self,
            tenant_id: &'a str,
            client_id: &'a str,
            input: &'a VerifiedInput,
        ) -> FapiFuture<'a, Result<(), FapiSignatureVerificationError>> {
            Box::pin(async move {
                let tenant_id = uuid::Uuid::parse_str(tenant_id)
                    .map_err(|_| FapiSignatureVerificationError::Invalid)?;
                let client = self
                    .clients
                    .by_client_id(tenant_id, client_id)
                    .await
                    .map_err(|_| FapiSignatureVerificationError::LookupUnavailable)?
                    .filter(|client| client.is_active)
                    .ok_or(FapiSignatureVerificationError::Invalid)?;
                if client.tenant_id != tenant_id || client.client_id != client_id {
                    return Err(FapiSignatureVerificationError::Invalid);
                }
                let jwks = client
                    .jwks
                    .as_ref()
                    .ok_or(FapiSignatureVerificationError::Invalid)?;
                nazo_http_signatures::verify_jwk_signature(
                    jwks,
                    input.keyid(),
                    input.algorithm(),
                    input.signature_base(),
                    input.signature(),
                )
                .map_err(|_| FapiSignatureVerificationError::Invalid)?;
                match self
                    .replay
                    .consume_fapi_http_signature(input.replay_fingerprint(), self.max_age_seconds)
                    .await
                {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(FapiSignatureVerificationError::Replay),
                    Err(_) => Err(FapiSignatureVerificationError::ReplayUnavailable),
                }
            })
        }

        fn response_signature(
            &self,
        ) -> Result<Arc<dyn FapiResponseSignature>, FapiSignatureOperationError> {
            self.keyset
                .prepare_http_signing()
                .map(|lease| Arc::new(ServerResponseSignature(lease)) as Arc<_>)
                .map_err(|_| FapiSignatureOperationError::Unavailable)
        }
    }

    struct ServerResponseSignature(HttpSigningLease);

    impl FapiResponseSignature for ServerResponseSignature {
        fn kid(&self) -> &str {
            self.0.kid()
        }

        fn algorithm(&self) -> &str {
            self.0.algorithm()
        }

        fn sign<'a>(
            &'a self,
            signature_base: &'a [u8],
        ) -> FapiFuture<'a, Result<Vec<u8>, FapiSignatureOperationError>> {
            Box::pin(async move {
                self.0
                    .sign(signature_base)
                    .await
                    .map(|signature| signature.as_bytes().to_vec())
                    .map_err(|_| FapiSignatureOperationError::Unavailable)
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use std::sync::Arc;

        use super::same_key_generation;

        #[test]
        fn verifier_cache_hits_only_the_same_live_snapshot_generation() {
            let original_manager = crate::test_support::test_key_manager();
            let original = original_manager.snapshot();
            let same_generation = original_manager.snapshot();
            assert!(same_key_generation(&original, &same_generation));

            // Test managers intentionally reuse the same public kid. Distinct
            // key material must still be treated as a rotation and miss.
            let rotated = crate::test_support::test_key_manager().snapshot();
            assert_eq!(original.active_kid, rotated.active_kid);
            assert!(!Arc::ptr_eq(&original, &rotated));
            assert_ne!(original.jwks(), rotated.jwks());
            assert!(!same_key_generation(&original, &rotated));
        }
    }
}

pub(crate) use production::{
    ServerFapiHttpMessageSignatures, ServerFapiMtlsResolver, ServerFapiResourceAuthorizer,
};
