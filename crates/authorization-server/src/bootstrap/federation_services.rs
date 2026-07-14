use serde_json::json;

use crate::adapters::audit::audit_event;
use crate::adapters::audit::audit_fields;
use crate::adapters::security::PasswordHashingError;
use crate::adapters::security::blake3_hex;
use crate::adapters::security::hash_password_blocking_limited;
use crate::adapters::security::random_urlsafe_token;

#[derive(Clone, Copy)]
pub(crate) struct FederationBootstrapPasswordHasher;

impl nazo_identity::ports::FederationPasswordHasherPort for FederationBootstrapPasswordHasher {
    fn hash_bootstrap_secret(
        &self,
    ) -> nazo_identity::ports::RepositoryFuture<'_, nazo_identity::ports::PasswordHashInput> {
        Box::pin(async move {
            let hash = hash_password_blocking_limited(random_urlsafe_token())
                .await
                .map_err(|error| match error {
                    PasswordHashingError::Saturated | PasswordHashingError::WorkerFailed => {
                        nazo_identity::ports::RepositoryError::Unavailable
                    }
                    PasswordHashingError::HashFailed => {
                        nazo_identity::ports::RepositoryError::Unexpected(
                            "Argon2 password hashing failed".to_owned(),
                        )
                    }
                })?;
            nazo_identity::ports::PasswordHashInput::new(hash).map_err(|error| {
                nazo_identity::ports::RepositoryError::Unexpected(error.to_string())
            })
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct TracingFederationAudit;

impl nazo_identity::ports::FederationAuditPort for TracingFederationAudit {
    fn record(&self, event: nazo_identity::FederationAuditEvent) {
        match event {
            nazo_identity::FederationAuditEvent::RelinkDenied {
                provider_type,
                provider_id,
                email,
            } => audit_event(
                "external_identity_relink_denied",
                audit_fields(&[
                    ("provider_type", json!(provider_type)),
                    ("provider_id", json!(provider_id)),
                    ("email_hash", json!(blake3_hex(&email))),
                ]),
            ),
            nazo_identity::FederationAuditEvent::IdentityLinked {
                user_id,
                provider_type,
                provider_id,
            } => audit_event(
                "external_identity_linked",
                audit_fields(&[
                    ("user_id", json!(user_id.as_uuid())),
                    ("provider_type", json!(provider_type)),
                    ("provider_id", json!(provider_id)),
                ]),
            ),
            nazo_identity::FederationAuditEvent::LoginSuccess {
                user_id,
                method,
                source_ip,
            } => audit_event(
                "federation_login_success",
                audit_fields(&[
                    ("user_id", json!(user_id.as_uuid())),
                    ("method", json!(method)),
                    ("source_ip_hash", json!(blake3_hex(&source_ip))),
                ]),
            ),
            nazo_identity::FederationAuditEvent::ProviderMismatchRejected {
                expected_provider_id,
                actual_provider_id,
            } => audit_event(
                "federation_provider_mismatch_rejected",
                audit_fields(&[
                    ("expected_provider_id", json!(expected_provider_id)),
                    ("actual_provider_id", json!(actual_provider_id)),
                ]),
            ),
            nazo_identity::FederationAuditEvent::SamlReplayRejected => {
                audit_event("federation_saml_replay_rejected", serde_json::Map::new())
            }
        }
    }
}

pub(crate) type LocalFederationService = nazo_identity::FederationService<
    nazo_postgres::FederationRepository,
    nazo_valkey::AuthenticationStore,
    FederationBootstrapPasswordHasher,
    nazo_valkey::SessionStore,
    TracingFederationAudit,
>;
