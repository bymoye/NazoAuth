use serde_json::json;

use crate::adapters::{
    audit::{audit_event, audit_fields},
    security::blake3_hex,
};

pub(crate) const PASSKEY_CEREMONY_TTL_SECONDS: u64 = 300;

#[derive(Clone, Copy)]
pub(crate) struct TracingPasskeyAudit;

impl nazo_identity::ports::PasskeyAuditPort for TracingPasskeyAudit {
    fn record(&self, event: nazo_identity::PasskeyAuditEvent) {
        match event {
            nazo_identity::PasskeyAuditEvent::LoginFailureEmail { email, reason } => audit_event(
                "passkey_login_failure",
                audit_fields(&[
                    ("email_hash", json!(blake3_hex(&email))),
                    ("reason", json!(reason.as_str())),
                ]),
            ),
            nazo_identity::PasskeyAuditEvent::LoginFailureUser { user_id, reason } => audit_event(
                "passkey_login_failure",
                audit_fields(&[
                    ("user_id", json!(user_id.as_uuid())),
                    ("reason", json!(reason.as_str())),
                ]),
            ),
            nazo_identity::PasskeyAuditEvent::LoginSuccess { user_id, source_ip } => audit_event(
                "passkey_login_success",
                audit_fields(&[
                    ("user_id", json!(user_id.as_uuid())),
                    ("source_ip_hash", json!(blake3_hex(&source_ip))),
                ]),
            ),
            nazo_identity::PasskeyAuditEvent::RegistrationRejected { user_id, reason } => {
                audit_event(
                    "passkey_registration_rejected",
                    audit_fields(&[
                        ("user_id", json!(user_id.as_uuid())),
                        ("reason", json!(reason.as_str())),
                    ]),
                );
            }
            nazo_identity::PasskeyAuditEvent::Registered {
                user_id,
                credential_id,
            } => audit_event(
                "passkey_registered",
                audit_fields(&[
                    ("user_id", json!(user_id.as_uuid())),
                    ("credential_id", json!(credential_id)),
                ]),
            ),
        }
    }
}

pub(crate) type LocalPasskeyService = nazo_identity::PasskeyService<
    nazo_postgres::UserRepository,
    nazo_postgres::PasskeyRepository,
    nazo_valkey::AuthenticationStore,
    nazo_postgres::MfaRepository,
    nazo_valkey::SessionStore,
    TracingPasskeyAudit,
>;
