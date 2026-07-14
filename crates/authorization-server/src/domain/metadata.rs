use std::sync::Arc;

use nazo_auth::{CibaMetadataProfile, MetadataAuthorizationServerProfile, MetadataSubjectType};
use nazo_http_actix::{MetadataEndpointConfig, MetadataSnapshot, MetadataSnapshotSource};
use nazo_key_management::{KeyManager, signing_algorithm_name};

use crate::runtime_modules::ServerRuntimeModuleRegistry;
use crate::settings::{AuthorizationServerProfile, CibaSecurityProfile, Settings, SubjectType};

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
    pub(crate) request_uri_parameter_enabled: bool,
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
            request_uri_parameter_enabled: self.request_uri_parameter_enabled,
        }
    }
}

impl From<&Settings> for MetadataConfig {
    fn from(settings: &Settings) -> Self {
        let endpoint = &settings.endpoint;
        let protocol = &settings.protocol;
        let modules = &settings.modules;
        Self {
            issuer: endpoint.issuer.clone(),
            mtls_endpoint_base_url: endpoint.mtls_endpoint_base_url.clone(),
            mtls_enabled: !endpoint.trusted_proxy_cidrs.is_empty(),
            authorization_server_profile: match protocol.authorization_server_profile {
                AuthorizationServerProfile::Oauth2Baseline => {
                    MetadataAuthorizationServerProfile::Oauth2Baseline
                }
                AuthorizationServerProfile::Fapi2Security => {
                    MetadataAuthorizationServerProfile::Fapi2Security
                }
                AuthorizationServerProfile::Fapi2MessageSigningAuthzRequest => {
                    MetadataAuthorizationServerProfile::Fapi2MessageSigningAuthorizationRequest
                }
                AuthorizationServerProfile::Fapi2MessageSigningJarm => {
                    MetadataAuthorizationServerProfile::Fapi2MessageSigningJarm
                }
                AuthorizationServerProfile::Fapi2MessageSigningIntrospection => {
                    MetadataAuthorizationServerProfile::Fapi2MessageSigningIntrospection
                }
            },
            ciba_security_profile: match protocol.ciba_security_profile {
                CibaSecurityProfile::FapiCibaId1PlainPrivateKeyJwtPoll => {
                    CibaMetadataProfile::FapiCiba
                }
                CibaSecurityProfile::Fapi2Ciba => CibaMetadataProfile::Fapi2Ciba,
            },
            subject_type: match protocol.subject_type {
                SubjectType::Public => MetadataSubjectType::Public,
                SubjectType::Pairwise => MetadataSubjectType::Pairwise,
            },
            pairwise_subject_enabled: protocol.pairwise_subject_secret.is_some(),
            protected_resource_identifier: protocol.protected_resource_identifier.to_owned(),
            require_pushed_authorization_requests: protocol.require_pushed_authorization_requests
                || protocol
                    .authorization_server_profile
                    .requires_fapi2_security(),
            request_uri_parameter_enabled: modules.enable_request_uri_parameter,
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
mod tests {
    use nazo_auth::{CibaMetadataProfile, MetadataAuthorizationServerProfile, MetadataSubjectType};

    use super::*;
    use crate::config::ConfigSource;
    use crate::http::client_ip::IpCidr;

    fn settings() -> Settings {
        Settings::from_config(&ConfigSource::default()).expect("default settings")
    }

    #[test]
    fn metadata_config_maps_only_the_focused_settings_boundary() {
        let mut settings = settings();
        settings.endpoint.issuer = "https://issuer.example".to_owned();
        settings.endpoint.mtls_endpoint_base_url = "https://mtls.issuer.example".to_owned();
        settings.endpoint.trusted_proxy_cidrs =
            vec![IpCidr::parse("192.0.2.0/24").expect("trusted proxy CIDR")];
        settings.protocol.subject_type = SubjectType::Pairwise;
        settings.protocol.pairwise_subject_secret = Some("a".repeat(32));
        settings.protocol.protected_resource_identifier = "https://resource.example".to_owned();
        settings.protocol.require_pushed_authorization_requests = true;
        settings.modules.enable_request_uri_parameter = true;

        assert_eq!(
            MetadataConfig::from(&settings).endpoint_config(),
            MetadataEndpointConfig {
                issuer: "https://issuer.example".to_owned(),
                mtls_endpoint_base_url: "https://mtls.issuer.example".to_owned(),
                mtls_enabled: true,
                authorization_server_profile: MetadataAuthorizationServerProfile::Oauth2Baseline,
                ciba_profile: CibaMetadataProfile::FapiCiba,
                subject_type: MetadataSubjectType::Pairwise,
                pairwise_subject_enabled: true,
                protected_resource_identifier: "https://resource.example".to_owned(),
                require_pushed_authorization_requests: true,
                request_uri_parameter_enabled: true,
            }
        );
    }

    #[test]
    fn metadata_config_maps_every_authorization_server_profile() {
        let cases = [
            (
                AuthorizationServerProfile::Oauth2Baseline,
                MetadataAuthorizationServerProfile::Oauth2Baseline,
                false,
            ),
            (
                AuthorizationServerProfile::Fapi2Security,
                MetadataAuthorizationServerProfile::Fapi2Security,
                true,
            ),
            (
                AuthorizationServerProfile::Fapi2MessageSigningAuthzRequest,
                MetadataAuthorizationServerProfile::Fapi2MessageSigningAuthorizationRequest,
                true,
            ),
            (
                AuthorizationServerProfile::Fapi2MessageSigningJarm,
                MetadataAuthorizationServerProfile::Fapi2MessageSigningJarm,
                true,
            ),
            (
                AuthorizationServerProfile::Fapi2MessageSigningIntrospection,
                MetadataAuthorizationServerProfile::Fapi2MessageSigningIntrospection,
                true,
            ),
        ];

        for (profile, expected, requires_par) in cases {
            let mut settings = settings();
            settings.protocol.authorization_server_profile = profile;
            settings.protocol.require_pushed_authorization_requests = false;
            let config = MetadataConfig::from(&settings);
            assert_eq!(config.authorization_server_profile, expected);
            assert_eq!(config.require_pushed_authorization_requests, requires_par);
        }
    }

    #[test]
    fn metadata_config_maps_both_ciba_profiles() {
        for (profile, expected) in [
            (
                CibaSecurityProfile::FapiCibaId1PlainPrivateKeyJwtPoll,
                CibaMetadataProfile::FapiCiba,
            ),
            (
                CibaSecurityProfile::Fapi2Ciba,
                CibaMetadataProfile::Fapi2Ciba,
            ),
        ] {
            let mut settings = settings();
            settings.protocol.ciba_security_profile = profile;
            assert_eq!(
                MetadataConfig::from(&settings).ciba_security_profile,
                expected
            );
        }
    }
}
