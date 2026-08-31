#![forbid(unsafe_code)]

//! Valkey composition adapter for the backend-neutral authorization server.
//!
//! This crate owns Valkey configuration, connection setup, namespace binding,
//! and translation into semantic transient-state ports. Persistent storage is
//! deliberately outside this boundary.

use std::sync::Arc;

use nazo_oauth_server::{
    FapiHttpSignatureReplayConsumption, FapiHttpSignatureReplayStore,
    FapiHttpSignatureReplayStoreError,
    bootstrap::{
        CibaPingDelivery, CibaPingDeliveryPort, CibaPingFinishOutcome, CibaPingFinishResult,
        ServerStateBackendBindings, ServerTransientStateBindings, ServerTransientStateProvider,
        TenantDirectoryCachePort, TenantTransientStateFactory, TransientStateError,
        TransientStateFuture, TransientStateHealthPort,
    },
    cli::{LauncherFuture, TransientStateLauncher},
    config::{ConfigSource, ServerConfigExtension},
};

#[derive(Clone)]
struct ValkeyHealth {
    connection: nazo_valkey::ValkeyConnection,
}

impl TransientStateHealthPort for ValkeyHealth {
    fn check(&self) -> TransientStateFuture<'_, ()> {
        Box::pin(async move {
            self.connection
                .health_check()
                .await
                .map_err(map_transient_state_error)
        })
    }
}

#[derive(Clone)]
struct ValkeyCibaPingDelivery {
    store: nazo_valkey::CibaStore,
}

impl CibaPingDeliveryPort for ValkeyCibaPingDelivery {
    fn claim_due<'a>(
        &'a self,
        now: i64,
        lock_until: i64,
        limit: usize,
    ) -> TransientStateFuture<'a, Vec<CibaPingDelivery>> {
        Box::pin(async move {
            self.store
                .claim_due_ping(now, lock_until, limit)
                .await
                .map(|deliveries| {
                    deliveries
                        .into_iter()
                        .map(|delivery| CibaPingDelivery {
                            auth_req_id_hash: delivery.auth_req_id_hash,
                            auth_req_id: delivery.auth_req_id,
                            endpoint: delivery.endpoint,
                            client_notification_token: delivery.client_notification_token,
                            attempts: delivery.attempts,
                            expires_at: delivery.expires_at,
                        })
                        .collect()
                })
                .map_err(map_transient_state_error)
        })
    }

    fn finish<'a>(
        &'a self,
        delivery: &'a CibaPingDelivery,
        outcome: CibaPingFinishOutcome,
    ) -> TransientStateFuture<'a, CibaPingFinishResult> {
        Box::pin(async move {
            let adapter_delivery = nazo_valkey::CibaPingDelivery {
                auth_req_id_hash: delivery.auth_req_id_hash.clone(),
                auth_req_id: delivery.auth_req_id.clone(),
                endpoint: delivery.endpoint.clone(),
                client_notification_token: delivery.client_notification_token.clone(),
                attempts: delivery.attempts,
                expires_at: delivery.expires_at,
            };
            let adapter_outcome = match outcome {
                CibaPingFinishOutcome::Delivered => nazo_valkey::CibaPingFinishOutcome::Delivered,
                CibaPingFinishOutcome::RetryAt(at) => {
                    nazo_valkey::CibaPingFinishOutcome::RetryAt(at)
                }
                CibaPingFinishOutcome::Failed => nazo_valkey::CibaPingFinishOutcome::Failed,
            };
            self.store
                .finish_ping(&adapter_delivery, adapter_outcome)
                .await
                .map(|result| match result {
                    nazo_valkey::CibaPingFinishResult::Applied => CibaPingFinishResult::Applied,
                    nazo_valkey::CibaPingFinishResult::Missing => CibaPingFinishResult::Missing,
                    nazo_valkey::CibaPingFinishResult::Conflict => CibaPingFinishResult::Conflict,
                })
                .map_err(map_transient_state_error)
        })
    }
}

#[derive(Clone)]
struct ValkeyFapiHttpSignatureReplay {
    store: nazo_valkey::ReplayStore,
}

impl FapiHttpSignatureReplayStore for ValkeyFapiHttpSignatureReplay {
    fn consume<'a>(
        &'a self,
        tenant_id: nazo_identity::TenantId,
        fingerprint: &'a [u8],
        ttl_seconds: i64,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        FapiHttpSignatureReplayConsumption,
                        FapiHttpSignatureReplayStoreError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let fingerprint: &[u8; 32] = fingerprint
                .try_into()
                .map_err(|_| FapiHttpSignatureReplayStoreError)?;
            self.store
                .consume_fapi_http_signature(tenant_id, fingerprint, ttl_seconds)
                .await
                .map(|accepted| {
                    if accepted {
                        FapiHttpSignatureReplayConsumption::Accepted
                    } else {
                        FapiHttpSignatureReplayConsumption::Replay
                    }
                })
                .map_err(|_| FapiHttpSignatureReplayStoreError)
        })
    }
}

#[derive(Clone)]
struct ValkeyProvider {
    connection: nazo_valkey::ValkeyConnection,
}

#[derive(Clone)]
struct ValkeyProviderFactory {
    client: nazo_valkey::ValkeyClient,
}

impl TenantTransientStateFactory for ValkeyProviderFactory {
    fn for_tenant(
        &self,
        tenant_id: nazo_identity::TenantId,
    ) -> Result<ServerTransientStateBindings, TransientStateError> {
        Ok(ServerTransientStateBindings::new(Arc::new(
            ValkeyProvider {
                connection: self.client.for_tenant(tenant_id),
            },
        )))
    }
}

#[derive(Clone)]
struct ValkeyTenantDirectoryCache {
    cache: nazo_valkey::TenantDirectoryCache,
}

impl TenantDirectoryCachePort for ValkeyTenantDirectoryCache {
    fn load(&self) -> TransientStateFuture<'_, Option<nazo_identity::TenantDirectorySnapshot>> {
        Box::pin(async move { self.cache.load().await.map_err(map_transient_state_error) })
    }

    fn publish_authoritative<'a>(
        &'a self,
        snapshot: &'a nazo_identity::TenantDirectorySnapshot,
    ) -> TransientStateFuture<'a, bool> {
        Box::pin(async move {
            self.cache
                .publish_authoritative(snapshot)
                .await
                .map_err(map_transient_state_error)
        })
    }
}

impl ServerTransientStateProvider for ValkeyProvider {
    fn health(&self) -> Arc<dyn TransientStateHealthPort> {
        Arc::new(ValkeyHealth {
            connection: self.connection.clone(),
        })
    }

    fn authorization_state(&self) -> Arc<dyn nazo_auth::AuthorizationStateStorePort> {
        Arc::new(nazo_valkey::AuthorizationStateAdapter::new(
            &self.connection,
        ))
    }

    fn token_state(&self) -> Arc<dyn nazo_auth::TokenStateStorePort> {
        Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(
            &self.connection,
        ))
    }

    fn ciba_state(
        &self,
    ) -> Arc<dyn nazo_auth::CibaStateStorePort<Version = nazo_auth::CibaStateVersion>> {
        Arc::new(nazo_valkey::CibaStore::new(&self.connection))
    }

    fn ciba_ping_deliveries(&self) -> Arc<dyn CibaPingDeliveryPort> {
        Arc::new(ValkeyCibaPingDelivery {
            store: nazo_valkey::CibaStore::new(&self.connection),
        })
    }

    fn device_state(
        &self,
    ) -> Arc<dyn nazo_auth::DeviceStateStorePort<Version = nazo_auth::DeviceStateVersion>> {
        Arc::new(nazo_valkey::DeviceStore::new(&self.connection))
    }

    fn dpop_state(&self) -> Arc<dyn nazo_auth::DpopStateStorePort> {
        Arc::new(nazo_valkey::ReplayStore::new(&self.connection))
    }

    fn protected_resource_dpop_state(
        &self,
    ) -> Arc<dyn nazo_resource_server::ProtectedResourceDpopStateStore> {
        Arc::new(nazo_valkey::ReplayStore::new(&self.connection))
    }

    fn fapi_http_signature_replay(&self) -> Arc<dyn FapiHttpSignatureReplayStore> {
        Arc::new(ValkeyFapiHttpSignatureReplay {
            store: nazo_valkey::ReplayStore::new(&self.connection),
        })
    }

    fn request_rate_limits(&self) -> Arc<dyn nazo_auth::RequestRateLimitPort> {
        Arc::new(nazo_valkey::RateLimitStore::new(&self.connection))
    }

    fn email_verification(&self) -> Arc<dyn nazo_identity::ports::EmailVerificationStorePort> {
        Arc::new(nazo_valkey::AuthenticationStore::new(&self.connection))
    }

    fn passkey_ceremonies(&self) -> Arc<dyn nazo_identity::ports::PasskeyCeremonyPort> {
        Arc::new(nazo_valkey::AuthenticationStore::new(&self.connection))
    }

    fn federation_state(&self) -> Arc<dyn nazo_identity::ports::FederationStatePort> {
        Arc::new(nazo_valkey::AuthenticationStore::new(&self.connection))
    }

    fn login_sessions(&self) -> Arc<dyn nazo_identity::ports::LoginSessionPort> {
        Arc::new(nazo_valkey::SessionStore::new(&self.connection))
    }

    fn sessions(&self) -> Arc<dyn nazo_identity::ports::SessionStorePort> {
        Arc::new(nazo_valkey::SessionStore::new(&self.connection))
    }

    fn login_throttle(&self) -> Arc<dyn nazo_identity::ports::LoginThrottlePort> {
        Arc::new(nazo_valkey::RateLimitStore::new(&self.connection))
    }

    fn mfa_attempt_throttle(&self) -> Arc<dyn nazo_identity::ports::MfaAttemptThrottlePort> {
        Arc::new(nazo_valkey::RateLimitStore::new(&self.connection))
    }

    fn delivery(&self) -> Arc<dyn nazo_identity::ports::DeliveryStorePort> {
        Arc::new(nazo_valkey::DeliveryStore::new(&self.connection))
    }
}

fn map_transient_state_error(error: nazo_valkey::Error) -> TransientStateError {
    match error.kind() {
        nazo_valkey::ErrorKind::Timeout | nazo_valkey::ErrorKind::Unavailable => {
            TransientStateError::Unavailable
        }
        nazo_valkey::ErrorKind::Protocol | nazo_valkey::ErrorKind::CorruptData => {
            TransientStateError::CorruptData
        }
        nazo_valkey::ErrorKind::UnexpectedResult => TransientStateError::Unexpected,
    }
}

/// Selects Valkey as the server's transient-state backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct ValkeyTransientStateLauncher;

impl TransientStateLauncher for ValkeyTransientStateLauncher {
    fn server_config_extension(&self) -> ServerConfigExtension {
        ServerConfigExtension::new(
            "VALKEY_URL: \"redis://127.0.0.1:6379/0\"\n".to_owned(),
            vec![
                "VALKEY_COMMAND_TIMEOUT_MS",
                "VALKEY_STATE_EPOCH",
                "VALKEY_URL",
            ],
            "VALKEY_STATE_EPOCH",
        )
    }

    fn server_bindings<'a>(
        &'a self,
        source: &'a ConfigSource,
        deployment_id: &'a str,
    ) -> LauncherFuture<'a, ServerStateBackendBindings> {
        Box::pin(async move {
            let state_epoch = source.transient_state_epoch()?;
            let url = source.string("VALKEY_URL", "redis://127.0.0.1:6379/0");
            let command_timeout_ms = source.parse::<u64>("VALKEY_COMMAND_TIMEOUT_MS", 1_000)?;
            if command_timeout_ms == 0 {
                anyhow::bail!("VALKEY_COMMAND_TIMEOUT_MS must be greater than zero");
            }
            let client = nazo_valkey::ValkeyClient::connect(
                &url,
                std::time::Duration::from_millis(command_timeout_ms),
                deployment_id,
                state_epoch,
            )
            .await?;
            Ok(ServerStateBackendBindings::new(
                Arc::new(ValkeyProviderFactory {
                    client: client.clone(),
                }),
                Arc::new(ValkeyTenantDirectoryCache {
                    cache: nazo_valkey::TenantDirectoryCache::new(&client),
                }),
            ))
        })
    }
}
