use nazo_runtime_modules::{ActiveModuleSnapshot, ModuleId};

use crate::GrantType;

mod document;

pub use document::{
    AuthorizationServerMetadataInput, CibaMetadataProfile, MetadataAuthorizationServerProfile,
    MetadataSigningAlgorithms, MetadataSubjectType, ProtectedResourceMetadataInput,
    authorization_server_metadata, protected_resource_metadata,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityAdmission {
    NewRequest,
    ExistingTransaction,
}

#[must_use]
pub fn module_admissible(
    snapshot: &ActiveModuleSnapshot,
    module: ModuleId,
    admission: CapabilityAdmission,
) -> bool {
    snapshot.accepting.contains(&module)
        || (matches!(admission, CapabilityAdmission::ExistingTransaction)
            && snapshot.draining.contains(&module))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataCapabilities {
    pub grant_types: Vec<&'static str>,
    pub device_authorization: bool,
    pub ciba: bool,
    pub dynamic_client_registration: bool,
    pub request_objects: bool,
    pub jarm: bool,
    pub authorization_details: bool,
    pub http_message_signatures: bool,
    pub scim: bool,
    pub native_sso: bool,
    pub frontchannel_logout: bool,
    pub session_management: bool,
}

impl MetadataCapabilities {
    #[must_use]
    pub fn from_snapshot(snapshot: &ActiveModuleSnapshot) -> Self {
        let visible = |module| module_admissible(snapshot, module, CapabilityAdmission::NewRequest);
        let device_authorization = visible(ModuleId::DeviceAuthorization);
        let ciba = visible(ModuleId::Ciba);
        let mut grant_types = vec![
            GrantType::AuthorizationCode.as_str(),
            GrantType::RefreshToken.as_str(),
            GrantType::ClientCredentials.as_str(),
        ];
        if visible(ModuleId::JwtBearerGrant) {
            grant_types.push(GrantType::JwtBearer.as_str());
        }
        if visible(ModuleId::TokenExchange) {
            grant_types.push(GrantType::TokenExchange.as_str());
        }
        if device_authorization {
            grant_types.push(GrantType::DeviceCode.as_str());
        }
        if ciba {
            grant_types.push(GrantType::Ciba.as_str());
        }

        Self {
            grant_types,
            device_authorization,
            ciba,
            dynamic_client_registration: visible(ModuleId::DynamicClientRegistration),
            request_objects: visible(ModuleId::RequestObjects),
            jarm: visible(ModuleId::Jarm),
            authorization_details: visible(ModuleId::AuthorizationDetails),
            http_message_signatures: visible(ModuleId::HttpMessageSignatures),
            scim: visible(ModuleId::Scim),
            native_sso: visible(ModuleId::NativeSso),
            frontchannel_logout: visible(ModuleId::FrontchannelLogout),
            session_management: visible(ModuleId::SessionManagement),
        }
    }
}
