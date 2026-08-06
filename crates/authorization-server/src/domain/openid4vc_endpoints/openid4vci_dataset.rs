use super::helpers::*;

use std::sync::Arc;

use chrono::Utc;
use nazo_identity::{TenantId, UserId};
use nazo_openid4vc_http_actix::CredentialHttpError;
use nazo_openid4vci::CredentialConfiguration;
use serde_json::Value;
use uuid::Uuid;

use super::openid4vci::{
    CredentialDatasetResponse, PutCredentialDatasetRequest, ServerCredentialIssuerOperations,
};

#[derive(Clone)]
pub(crate) struct CredentialDatasetAdminService {
    issuer: Arc<ServerCredentialIssuerOperations>,
}

impl CredentialDatasetAdminService {
    pub(crate) fn new(issuer: Arc<ServerCredentialIssuerOperations>) -> Self {
        Self { issuer }
    }

    pub(crate) async fn put_dataset(
        &self,
        tenant_id: Uuid,
        actor_user_id: Uuid,
        subject_id: Uuid,
        configuration_id: String,
        request: PutCredentialDatasetRequest,
    ) -> Result<CredentialDatasetResponse, CredentialHttpError> {
        self.require_configured_tenant(tenant_id)?;
        if !self.enabled(nazo_auth::CapabilityAdmission::NewRequest) {
            return Err(vci_error(
                503,
                "temporarily_unavailable",
                "Credential issuer is unavailable.",
            ));
        }
        let Some(configuration) = self.configurations.get(&configuration_id) else {
            return Err(vci_error(
                400,
                "invalid_request",
                "Credential configuration is unknown.",
            ));
        };
        validate_managed_dataset(configuration, &request)?;
        let tenant = TenantId::new(self.tenant_id)
            .map_err(|_| vci_error(500, "server_error", "Credential tenant is invalid."))?;
        let subject = UserId::new(subject_id)
            .map_err(|_| vci_error(400, "invalid_request", "Credential subject is invalid."))?;
        if !self
            .users
            .is_active_by_tenant_id(tenant, subject)
            .await
            .map_err(|_| vci_error(503, "server_error", "Credential subject lookup failed."))?
        {
            return Err(vci_error(
                404,
                "invalid_request",
                "Credential subject is not active.",
            ));
        }
        let stored = self
            .datasets
            .upsert_managed_dataset(nazo_postgres::ManagedCredentialDatasetWrite {
                tenant_id: self.tenant_id,
                actor_user_id,
                subject_id,
                credential_configuration_id: &configuration_id,
                claims: &request.claims,
                valid_from: request.valid_from,
                valid_until: request.valid_until,
            })
            .await
            .map_err(|_| {
                vci_error(
                    503,
                    "server_error",
                    "Credential dataset persistence failed.",
                )
            })?;
        if !stored {
            return Err(vci_error(
                404,
                "invalid_request",
                "Credential subject is not active.",
            ));
        }
        tracing::info!(%subject_id, %configuration_id, "issuer credential dataset updated");
        self.get_dataset(tenant_id, subject_id, configuration_id)
            .await
    }

    pub(crate) async fn get_dataset(
        &self,
        tenant_id: Uuid,
        subject_id: Uuid,
        configuration_id: String,
    ) -> Result<CredentialDatasetResponse, CredentialHttpError> {
        self.require_configured_tenant(tenant_id)?;
        if !self.configurations.contains_key(&configuration_id) {
            return Err(vci_error(
                404,
                "invalid_request",
                "Credential configuration is unknown.",
            ));
        }
        let dataset = self
            .datasets
            .managed_dataset(self.tenant_id, subject_id, &configuration_id)
            .await
            .map_err(|_| vci_error(503, "server_error", "Credential dataset lookup failed."))?
            .ok_or_else(|| {
                vci_error(404, "invalid_request", "Credential dataset was not found.")
            })?;
        Ok(CredentialDatasetResponse {
            subject_id,
            credential_configuration_id: configuration_id,
            claims: dataset.claims,
            valid_from: dataset.valid_from,
            valid_until: dataset.valid_until,
            updated_at: dataset.updated_at,
        })
    }

    pub(crate) async fn delete_dataset(
        &self,
        tenant_id: Uuid,
        actor_user_id: Uuid,
        subject_id: Uuid,
        configuration_id: String,
    ) -> Result<(), CredentialHttpError> {
        self.require_configured_tenant(tenant_id)?;
        if !self.configurations.contains_key(&configuration_id) {
            return Err(vci_error(
                404,
                "invalid_request",
                "Credential configuration is unknown.",
            ));
        }
        let deleted = self
            .datasets
            .delete_managed_dataset(self.tenant_id, actor_user_id, subject_id, &configuration_id)
            .await
            .map_err(|_| vci_error(503, "server_error", "Credential dataset deletion failed."))?;
        if !deleted {
            return Err(vci_error(
                404,
                "invalid_request",
                "Credential dataset was not found.",
            ));
        }
        tracing::info!(%subject_id, %configuration_id, "issuer credential dataset deleted");
        Ok(())
    }

    fn require_configured_tenant(&self, tenant_id: Uuid) -> Result<(), CredentialHttpError> {
        if tenant_id == self.tenant_id {
            Ok(())
        } else {
            Err(vci_error(
                404,
                "invalid_request",
                "Credential dataset was not found.",
            ))
        }
    }
}

impl std::ops::Deref for CredentialDatasetAdminService {
    type Target = ServerCredentialIssuerOperations;

    fn deref(&self) -> &Self::Target {
        &self.issuer
    }
}

pub(crate) fn validate_managed_dataset(
    configuration: &CredentialConfiguration,
    request: &PutCredentialDatasetRequest,
) -> Result<(), CredentialHttpError> {
    let Some(claims) = request
        .claims
        .as_object()
        .filter(|claims| !claims.is_empty())
    else {
        return Err(vci_error(
            400,
            "invalid_request",
            "Credential claims must be a non-empty object.",
        ));
    };
    let mut nodes = 0;
    if serde_json::to_vec(&request.claims).map_or(true, |value| value.len() > 64 * 1024)
        || !bounded_json(&request.claims, 0, &mut nodes)
    {
        return Err(vci_error(
            400,
            "invalid_request",
            "Credential claims exceed structural limits.",
        ));
    }
    if request.valid_until.is_some_and(|valid_until| {
        request
            .valid_from
            .map_or(valid_until <= Utc::now(), |valid_from| {
                valid_until <= valid_from
            })
    }) {
        return Err(vci_error(
            400,
            "invalid_request",
            "Credential dataset validity is invalid.",
        ));
    }
    match configuration.format {
        nazo_digital_credentials::CredentialFormat::SdJwtVc => {
            const RESERVED: &[&str] = &[
                "iss", "iat", "nbf", "exp", "vct", "_sd", "_sd_alg", "cnf", "status",
            ];
            if claims.keys().any(|name| {
                name.is_empty() || name.len() > 128 || RESERVED.contains(&name.as_str())
            }) {
                return Err(vci_error(
                    400,
                    "invalid_request",
                    "Credential claims contain a reserved or invalid name.",
                ));
            }
        }
        nazo_digital_credentials::CredentialFormat::MsoMdoc => {
            if claims.iter().any(|(namespace, values)| {
                namespace.is_empty()
                    || namespace.len() > 255
                    || values.as_object().is_none_or(|values| {
                        values.is_empty()
                            || values
                                .keys()
                                .any(|name| name.is_empty() || name.len() > 128)
                    })
            }) {
                return Err(vci_error(
                    400,
                    "invalid_request",
                    "mdoc claims must be non-empty namespace objects.",
                ));
            }
        }
    }
    Ok(())
}

fn bounded_json(value: &Value, depth: usize, nodes: &mut usize) -> bool {
    *nodes += 1;
    if depth > 8 || *nodes > 512 {
        return false;
    }
    match value {
        Value::Object(object) => object
            .iter()
            .all(|(key, value)| key.len() <= 255 && bounded_json(value, depth + 1, nodes)),
        Value::Array(array) => array
            .iter()
            .all(|value| bounded_json(value, depth + 1, nodes)),
        Value::String(value) => value.len() <= 4096,
        _ => true,
    }
}
