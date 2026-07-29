use nazo_auth::{CibaMetadataProfile, MetadataAuthorizationServerProfile, MetadataSubjectType};

use super::*;
use crate::config::ConfigSource;
use nazo_http_actix::IpCidr;

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

    assert_eq!(
        MetadataConfig::from(&settings).endpoint_config(),
        MetadataEndpointConfig {
            issuer: "https://issuer.example".to_owned(),
            mtls_endpoint_base_url: "https://mtls.issuer.example".to_owned(),
            mtls_enabled: true,
            authorization_server_profile: MetadataAuthorizationServerProfile::Composable,
            ciba_profile: CibaMetadataProfile::FapiCiba,
            subject_type: MetadataSubjectType::Pairwise,
            pairwise_subject_enabled: true,
            protected_resource_identifier: "https://resource.example".to_owned(),
            require_pushed_authorization_requests: true,
        }
    );
}

#[test]
fn metadata_config_uses_composable_discovery_for_every_legacy_profile() {
    let cases = [
        AuthorizationServerProfile::Oauth2Baseline,
        AuthorizationServerProfile::Fapi2Security,
        AuthorizationServerProfile::Fapi2MessageSigningAuthzRequest,
        AuthorizationServerProfile::Fapi2MessageSigningJarm,
        AuthorizationServerProfile::Fapi2MessageSigningIntrospection,
    ];

    for profile in cases {
        let mut settings = settings();
        settings.protocol.authorization_server_profile = profile;
        settings.protocol.require_pushed_authorization_requests = false;
        let config = MetadataConfig::from(&settings);
        assert_eq!(
            config.authorization_server_profile,
            MetadataAuthorizationServerProfile::Composable
        );
        assert!(!config.require_pushed_authorization_requests);
    }
}

#[test]
fn metadata_config_maps_both_ciba_profiles() {
    for (profile, expected) in [
        (
            CibaSecurityProfile::FapiCibaId1,
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
