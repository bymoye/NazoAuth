use std::sync::Arc;

use nazo_auth::{CibaMetadataProfile, MetadataAuthorizationServerProfile, MetadataSubjectType};
use nazo_http_actix::{MetadataEndpointConfig, MetadataSnapshot, MetadataSnapshotSource};
use nazo_key_management::{KeyManager, signing_algorithm_name};

use crate::http::mtls::MtlsCertificateSourceMode;
use crate::runtime_modules::ServerRuntimeModuleRegistry;
use crate::settings::{CibaSecurityProfile, Settings, SubjectType};

#[derive(Clone)]
pub(crate) struct MetadataConfig {
    pub(crate) issuer: String,
    pub(crate) mtls_endpoint_base_url: String,
    pub(crate) mtls_enabled: bool,
    pub(crate) authorization_server_profile: MetadataAuthorizationServerProfile,
    pub(crate) ciba_security_profile: CibaMetadataProfile,
    pub(crate) subject_type: MetadataSubjectType,
    pub(crate) pairwise_subject_enabled: bool,
    pub(crate) protected_resource_identifier: String,
    pub(crate) require_pushed_authorization_requests: bool,
}

impl MetadataConfig {
    pub(crate) fn endpoint_config(&self) -> MetadataEndpointConfig {
        MetadataEndpointConfig {
            issuer: self.issuer.clone(),
            mtls_endpoint_base_url: self.mtls_endpoint_base_url.clone(),
            mtls_enabled: self.mtls_enabled,
            authorization_server_profile: self.authorization_server_profile,
            ciba_profile: self.ciba_security_profile,
            subject_type: self.subject_type,
            pairwise_subject_enabled: self.pairwise_subject_enabled,
            protected_resource_identifier: self.protected_resource_identifier.clone(),
            require_pushed_authorization_requests: self.require_pushed_authorization_requests,
        }
    }
}

impl From<&Settings> for MetadataConfig {
    fn from(settings: &Settings) -> Self {
        let endpoint = &settings.endpoint;
        let protocol = &settings.protocol;
        Self {
            issuer: endpoint.issuer.clone(),
            mtls_endpoint_base_url: endpoint.mtls_endpoint_base_url.clone(),
            mtls_enabled: endpoint.mtls_certificate_source != MtlsCertificateSourceMode::Disabled,
            authorization_server_profile: MetadataAuthorizationServerProfile::Composable,
            ciba_security_profile: match protocol.ciba_security_profile {
                CibaSecurityProfile::FapiCibaId1 => CibaMetadataProfile::FapiCiba,
                CibaSecurityProfile::Fapi2Ciba => CibaMetadataProfile::Fapi2Ciba,
            },
            subject_type: match protocol.subject_type {
                SubjectType::Public => MetadataSubjectType::Public,
                SubjectType::Pairwise => MetadataSubjectType::Pairwise,
            },
            pairwise_subject_enabled: protocol.pairwise_subject_secret.is_some(),
            protected_resource_identifier: protocol.protected_resource_identifier.to_owned(),
            require_pushed_authorization_requests: protocol.require_pushed_authorization_requests,
        }
    }
}

/// Server-side adapter that exposes only public key and module snapshots to Actix.
pub(crate) struct ServerMetadataSnapshotSource {
    keyset: KeyManager,
    runtime_modules: Arc<ServerRuntimeModuleRegistry>,
}

impl ServerMetadataSnapshotSource {
    pub(crate) fn new(
        keyset: KeyManager,
        runtime_modules: Arc<ServerRuntimeModuleRegistry>,
    ) -> Self {
        Self {
            keyset,
            runtime_modules,
        }
    }
}

impl MetadataSnapshotSource for ServerMetadataSnapshotSource {
    fn snapshot(&self) -> MetadataSnapshot {
        let keys = self.keyset.snapshot();
        MetadataSnapshot {
            active_modules: self.runtime_modules.snapshot(),
            active_signing_algorithms: signing_algorithm_name(keys.active_alg)
                .into_iter()
                .collect(),
            id_token_signing_algorithms: keys.id_token_signing_alg_values_supported(),
            response_signing_algorithms: keys.response_signing_alg_values_supported(),
            jwks: keys.jwks(),
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/domain/metadata.rs"]
mod tests;
