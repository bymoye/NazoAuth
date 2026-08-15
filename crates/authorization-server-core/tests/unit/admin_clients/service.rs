use std::sync::{Arc, Mutex};

use nazo_identity::{OrganizationId, RealmId, TenantContext, TenantId};
use serde_json::Value;
use uuid::Uuid;

use super::*;
use crate::{
    AdminClientCryptoPort, AdminClientFuture, AdminClientPortError, AdminClientRepositoryPort,
    SectorIdentifierFuture, SectorIdentifierResolverPort,
};

#[derive(Clone, Default)]
struct CapturingRepository(Arc<Mutex<Vec<(Uuid, i64, i64)>>>);

impl AdminClientRepositoryPort for CapturingRepository {
    fn page(
        &self,
        tenant_id: Uuid,
        offset: i64,
        limit: i64,
    ) -> AdminClientFuture<'_, (Vec<OAuthClient>, i64)> {
        self.0.lock().unwrap().push((tenant_id, offset, limit));
        Box::pin(async { Ok((Vec::new(), 0)) })
    }

    fn by_client_id<'a>(
        &'a self,
        _tenant_id: Uuid,
        _client_id: &'a str,
    ) -> AdminClientFuture<'a, Option<OAuthClient>> {
        Box::pin(async { Err(AdminClientPortError::Unexpected) })
    }

    fn insert<'a>(
        &'a self,
        _client: &'a OAuthClient,
        _client_secret_hash: Option<&'a str>,
        _registration_access_token_blake3: Option<&'a str>,
    ) -> AdminClientFuture<'a, OAuthClient> {
        Box::pin(async { Err(AdminClientPortError::Unexpected) })
    }

    fn update<'a>(&'a self, _client: &'a OAuthClient) -> AdminClientFuture<'a, OAuthClient> {
        Box::pin(async { Err(AdminClientPortError::Unexpected) })
    }
}

#[derive(Clone, Copy)]
struct NoopSectorIdentifierResolver;

impl SectorIdentifierResolverPort for NoopSectorIdentifierResolver {
    fn resolve<'a>(&'a self, _uri: &'a str) -> SectorIdentifierFuture<'a> {
        Box::pin(async { Err("unexpected sector identifier lookup".to_owned()) })
    }
}

#[derive(Clone, Copy)]
struct NoopCrypto;

impl AdminClientCryptoPort for NoopCrypto {
    fn response_signing_algorithms(&self) -> Vec<String> {
        Vec::new()
    }

    fn issue_client_secret(&self, _pepper: &str) -> (String, String) {
        unreachable!("page does not issue client secrets")
    }

    fn validate_jwks(&self, _jwks: &Value) -> Result<(), String> {
        Err("page does not validate JWKS".to_owned())
    }

    fn validate_rfc4514_dn(&self, _value: &str) -> Result<(), String> {
        Err("page does not validate distinguished names".to_owned())
    }

    fn matching_encryption_key_count(&self, _jwks: &Value, _algorithm: &str) -> usize {
        0
    }

    fn contains_signing_key(&self, _jwks: &Value) -> bool {
        false
    }

    fn valid_self_signed_mtls_jwks(&self, _jwks: &Value) -> bool {
        false
    }
}

#[test]
fn page_forwards_the_policy_tenant_to_persistence() {
    let tenant = TenantContext {
        tenant_id: TenantId::new(Uuid::now_v7()).unwrap(),
        realm_id: RealmId::new(Uuid::now_v7()).unwrap(),
        organization_id: OrganizationId::new(Uuid::now_v7()).unwrap(),
    };
    let repository = CapturingRepository::default();
    let observed = repository.0.clone();
    let service = AdminClientService::new(
        repository,
        NoopSectorIdentifierResolver,
        NoopCrypto,
        AdminClientPolicy {
            tenant,
            pairwise_subject_secret: None,
            client_secret_pepper: "test-only".to_owned(),
        },
    );

    let (clients, total) = futures_executor::block_on(service.page(17, 23)).unwrap();
    assert!(clients.is_empty());
    assert_eq!(total, 0);
    assert_eq!(
        *observed.lock().unwrap(),
        vec![(tenant.tenant_id.as_uuid(), 17, 23)]
    );
}
