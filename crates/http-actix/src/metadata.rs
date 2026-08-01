use std::sync::Arc;

use actix_web::web::{Data, Json};
use nazo_auth::{
    AuthorizationServerMetadataInput, CibaMetadataProfile, MetadataAuthorizationServerProfile,
    MetadataSigningAlgorithms, MetadataSubjectType, ProtectedResourceMetadataInput,
    authorization_server_metadata, protected_resource_metadata,
};
use nazo_runtime_modules::ActiveModuleSnapshot;
use serde_json::Value;

/// Owned, transport-facing configuration used to render standard metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataEndpointConfig {
    pub issuer: String,
    pub mtls_endpoint_base_url: String,
    pub mtls_enabled: bool,
    pub authorization_server_profile: MetadataAuthorizationServerProfile,
    pub ciba_profile: CibaMetadataProfile,
    pub subject_type: MetadataSubjectType,
    pub pairwise_subject_enabled: bool,
    pub protected_resource_identifier: String,
    pub require_pushed_authorization_requests: bool,
}

/// One request's immutable view of module admission and public signing data.
#[derive(Clone, Debug)]
pub struct MetadataSnapshot {
    pub active_modules: Arc<ActiveModuleSnapshot>,
    pub active_signing_algorithms: Vec<&'static str>,
    pub id_token_signing_algorithms: Vec<&'static str>,
    pub response_signing_algorithms: Vec<&'static str>,
    pub jwks: Value,
}

/// Supplies public, request-facing snapshots without exposing key lifecycle or storage details.
pub trait MetadataSnapshotSource: Send + Sync {
    fn snapshot(&self) -> MetadataSnapshot;
}

/// Focused Actix dependency for discovery, RFC 8414/RFC 9728 metadata, and JWKS.
#[derive(Clone)]
pub struct MetadataHandles {
    config: MetadataEndpointConfig,
    snapshots: Arc<dyn MetadataSnapshotSource>,
}

impl MetadataHandles {
    #[must_use]
    pub fn new(config: MetadataEndpointConfig, snapshots: Arc<dyn MetadataSnapshotSource>) -> Self {
        Self { config, snapshots }
    }

    fn authorization_server_metadata(&self, snapshot: &MetadataSnapshot) -> Value {
        authorization_server_metadata(
            AuthorizationServerMetadataInput {
                issuer: &self.config.issuer,
                mtls_endpoint_base_url: &self.config.mtls_endpoint_base_url,
                mtls_enabled: self.config.mtls_enabled,
                profile: self.config.authorization_server_profile,
                ciba_profile: self.config.ciba_profile,
                subject_type: self.config.subject_type,
                pairwise_subject_enabled: self.config.pairwise_subject_enabled,
                protected_resource_identifier: &self.config.protected_resource_identifier,
                require_pushed_authorization_requests: self
                    .config
                    .require_pushed_authorization_requests,
                signing_algorithms: MetadataSigningAlgorithms {
                    active: &snapshot.active_signing_algorithms,
                    id_token: &snapshot.id_token_signing_algorithms,
                    response: &snapshot.response_signing_algorithms,
                },
            },
            &snapshot.active_modules,
        )
    }

    fn protected_resource_metadata(&self, snapshot: &MetadataSnapshot) -> Value {
        protected_resource_metadata(
            ProtectedResourceMetadataInput {
                issuer: &self.config.issuer,
                protected_resource_identifier: &self.config.protected_resource_identifier,
                mtls_enabled: self.config.mtls_enabled,
            },
            &snapshot.active_modules,
        )
    }
}

/// OIDC Discovery metadata. A single immutable snapshot is used for the whole document.
pub async fn discovery(handles: Data<MetadataHandles>) -> Json<Value> {
    let snapshot = handles.snapshots.snapshot();
    Json(handles.authorization_server_metadata(&snapshot))
}

/// RFC 8414 Authorization Server metadata.
pub async fn oauth_authorization_server_metadata(handles: Data<MetadataHandles>) -> Json<Value> {
    let snapshot = handles.snapshots.snapshot();
    Json(handles.authorization_server_metadata(&snapshot))
}

/// RFC 9728 Protected Resource metadata.
pub async fn oauth_protected_resource_metadata(handles: Data<MetadataHandles>) -> Json<Value> {
    let snapshot = handles.snapshots.snapshot();
    Json(handles.protected_resource_metadata(&snapshot))
}

/// Public JSON Web Key Set derived from the current key snapshot.
pub async fn jwks(handles: Data<MetadataHandles>) -> Json<Value> {
    Json(handles.snapshots.snapshot().jwks)
}

#[cfg(test)]
#[path = "../tests/unit/metadata.rs"]
mod tests;
