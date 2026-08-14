use base64::Engine as _;
use uuid::Uuid;

use super::{
    AdminClientCryptoPort, AdminClientError, AdminClientPolicy, AdminClientRepositoryPort,
    CreateClientRequest, CreatedClient, PatchClientRequest, PreparedClientRegistration,
    SectorIdentifierResolverPort, SuppliedClientSecret,
};
use crate::ClientSecretDigesterPort;
use crate::OAuthClient;

pub struct AdminClientService<R, S, C> {
    pub(super) repository: R,
    pub(super) sector_identifiers: S,
    pub(super) crypto: C,
    pub(super) policy: AdminClientPolicy,
}

impl<R, S, C> AdminClientService<R, S, C>
where
    R: AdminClientRepositoryPort,
    S: SectorIdentifierResolverPort,
    C: AdminClientCryptoPort,
{
    pub const fn new(
        repository: R,
        sector_identifiers: S,
        crypto: C,
        policy: AdminClientPolicy,
    ) -> Self {
        Self {
            repository,
            sector_identifiers,
            crypto,
            policy,
        }
    }

    pub async fn page(
        &self,
        offset: i64,
        limit: i64,
    ) -> Result<(Vec<OAuthClient>, i64), AdminClientError> {
        self.repository
            .page(self.policy.tenant.tenant_id.as_uuid(), offset, limit)
            .await
            .map_err(AdminClientError::Repository)
    }

    pub async fn detail(&self, client_id: &str) -> Result<OAuthClient, AdminClientError> {
        self.repository
            .by_client_id(self.policy.tenant.tenant_id.as_uuid(), client_id)
            .await
            .map_err(AdminClientError::Lookup)?
            .ok_or(AdminClientError::NotFound)
    }

    pub async fn create(
        &self,
        request: CreateClientRequest,
    ) -> Result<CreatedClient, AdminClientError> {
        let prepared = self.prepare_registration(request).await?;
        let issued_secret = prepared.issued_secret.clone();
        let client = insert_prepared_client(&self.repository, &prepared).await?;
        Ok(CreatedClient {
            client,
            issued_secret,
        })
    }

    /// Validate and prepare a registration for a caller that owns a wider transaction boundary.
    ///
    /// Access-request approval uses this path so the client row and approval state can still be
    /// committed by the PostgreSQL adapter in one transaction.
    pub async fn prepare_registration(
        &self,
        request: CreateClientRequest,
    ) -> Result<PreparedClientRegistration, AdminClientError> {
        super::registration::prepare_client_registration(
            request,
            &self.policy,
            &self.sector_identifiers,
            &self.crypto,
        )
        .await
    }

    pub async fn update(
        &self,
        client_id: &str,
        request: PatchClientRequest,
    ) -> Result<OAuthClient, AdminClientError> {
        let current = self.detail(client_id).await?;
        let updated = super::patch::prepare_client_patch(
            current,
            request,
            &self.policy,
            &self.sector_identifiers,
            &self.crypto,
        )
        .await?;
        self.repository
            .update(&updated)
            .await
            .map_err(AdminClientError::Write)
    }
}

pub async fn insert_prepared_client<R: AdminClientRepositoryPort>(
    repository: &R,
    prepared: &PreparedClientRegistration,
) -> Result<OAuthClient, AdminClientError> {
    let client = OAuthClient {
        id: Uuid::now_v7(),
        tenant_id: prepared.tenant.tenant_id.as_uuid(),
        realm_id: prepared.tenant.realm_id.as_uuid(),
        organization_id: prepared.tenant.organization_id.as_uuid(),
        registration: prepared.registration.clone(),
        require_mtls_bound_tokens: prepared.require_mtls_bound_tokens,
        is_active: true,
    };
    let inserted = repository
        .insert(
            &client,
            prepared.client_secret_hash.as_deref(),
            prepared.registration_access_token_blake3.as_deref(),
            prepared.conformance_lease_id,
        )
        .await
        .map_err(AdminClientError::Write)?;
    if inserted.tenant_id != client.tenant_id
        || inserted.realm_id != client.realm_id
        || inserted.organization_id != client.organization_id
    {
        return Err(AdminClientError::Consistency(
            "客户端写入后租户边界不匹配".to_owned(),
        ));
    }
    Ok(inserted)
}

#[cfg(test)]
#[path = "../../tests/unit/admin_clients/service.rs"]
mod tests;

impl<R, S, C> AdminClientService<R, S, C>
where
    R: AdminClientRepositoryPort,
    S: SectorIdentifierResolverPort,
    C: AdminClientCryptoPort + ClientSecretDigesterPort,
{
    /// Prepare a registration while binding a caller-supplied secret. This is
    /// restricted to the privileged conformance onboarding adapter; ordinary
    /// administrative registration continues to generate a fresh secret.
    pub async fn prepare_registration_with_secret(
        &self,
        request: CreateClientRequest,
        secret: SuppliedClientSecret,
    ) -> Result<PreparedClientRegistration, AdminClientError> {
        let requires_secret = request.client_type == "confidential"
            && matches!(
                request.token_endpoint_auth_method.as_str(),
                "client_secret_basic" | "client_secret_post"
            );
        if !requires_secret {
            return Err(AdminClientError::InvalidRequest(
                "supplied client secret is only valid for confidential client_secret auth"
                    .to_owned(),
            ));
        }
        let secret = secret.as_str().map_err(|_| {
            AdminClientError::InvalidRequest("supplied client secret is not UTF-8".to_owned())
        })?;
        let salt =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        let client_secret_hash =
            self.crypto
                .client_secret_digest(secret, &self.policy.client_secret_pepper, &salt);
        super::registration::prepare_client_registration_with_material(
            request,
            &self.policy,
            &self.sector_identifiers,
            &self.crypto,
            Some(secret.to_owned()),
            Some(client_secret_hash),
        )
        .await
    }
}
