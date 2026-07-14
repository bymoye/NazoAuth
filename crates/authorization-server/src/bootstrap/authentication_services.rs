use serde_json::json;

use crate::adapters::audit::audit_event;
use crate::adapters::audit::audit_fields;
use crate::adapters::security::PasswordVerificationError;
use crate::adapters::security::blake3_hex;
use crate::adapters::security::verify_password_blocking_limited;

#[derive(Clone, Copy)]
pub(crate) struct LoginPasswordVerifier;

impl nazo_identity::ports::SecretVerifyPort for LoginPasswordVerifier {
    fn verify_secret(
        &self,
        secret: String,
        password_hash: nazo_identity::PasswordHash,
    ) -> nazo_identity::ports::SecretVerifyFuture<'_> {
        Box::pin(async move {
            verify_password_blocking_limited(secret, password_hash)
                .await
                .map_err(|error| match error {
                    PasswordVerificationError::Saturated => {
                        nazo_identity::ports::SecretVerifyError::Busy
                    }
                    PasswordVerificationError::WorkerFailed => {
                        nazo_identity::ports::SecretVerifyError::Failed
                    }
                })
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct TracingAuthenticationAudit;

impl nazo_identity::ports::AuthenticationAuditPort for TracingAuthenticationAudit {
    fn record(&self, event: nazo_identity::ports::AuthenticationAuditEvent) {
        match event {
            nazo_identity::ports::AuthenticationAuditEvent::Failure {
                email,
                source_ip,
                user_id,
            } => {
                let mut fields = vec![
                    ("email_hash", json!(blake3_hex(&email))),
                    ("source_ip_hash", json!(blake3_hex(&source_ip))),
                ];
                if let Some(user_id) = user_id {
                    fields.push(("user_id", json!(user_id.as_uuid())));
                }
                audit_event("login_failure", audit_fields(&fields));
            }
            nazo_identity::ports::AuthenticationAuditEvent::Success {
                user_id,
                source_ip,
                amr,
            } => audit_event(
                "login_success",
                audit_fields(&[
                    ("user_id", json!(user_id.as_uuid())),
                    ("source_ip_hash", json!(blake3_hex(&source_ip))),
                    ("amr", json!(amr)),
                ]),
            ),
        }
    }
}

pub(crate) type LocalAuthenticationService = nazo_identity::AuthenticationService<
    nazo_postgres::UserRepository,
    nazo_valkey::RateLimitStore,
    LoginPasswordVerifier,
    nazo_postgres::MfaRepository,
    nazo_valkey::SessionStore,
    TracingAuthenticationAudit,
>;
