use uuid::Uuid;

use crate::{
    MtlsTrustAnchorRequest, MtlsTrustAnchorRequestPage, MtlsTrustAnchorStatus,
    NewMtlsTrustAnchorRequest, TenantId, UserId,
};

use super::RepositoryFuture;

/// Complete user/admin lifecycle for deployment mTLS trust anchors.
/// Approval, rejection and revocation must enforce tenant ownership, actor
/// authorization, limits and audit mutation atomically inside the adapter.
pub trait MtlsTrustAnchorStore: Send + Sync {
    fn create_for_owned_client(
        &self,
        request: NewMtlsTrustAnchorRequest,
    ) -> RepositoryFuture<'_, MtlsTrustAnchorRequest>;

    fn list_for_user(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Vec<MtlsTrustAnchorRequest>>;

    fn page(
        &self,
        tenant_id: TenantId,
        status: Option<MtlsTrustAnchorStatus>,
        limit: i64,
        offset: i64,
    ) -> RepositoryFuture<'_, MtlsTrustAnchorRequestPage>;

    fn by_id(
        &self,
        tenant_id: TenantId,
        id: Uuid,
    ) -> RepositoryFuture<'_, Option<MtlsTrustAnchorRequest>>;

    fn approve(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        actor: UserId,
        note: Option<String>,
    ) -> RepositoryFuture<'_, MtlsTrustAnchorRequest>;

    fn reject(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        actor: UserId,
        note: Option<String>,
    ) -> RepositoryFuture<'_, MtlsTrustAnchorRequest>;

    fn revoke(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        actor: UserId,
        note: String,
    ) -> RepositoryFuture<'_, MtlsTrustAnchorRequest>;

    fn active_bundle(
        &self,
        tenant_id: TenantId,
        client_id: Option<Uuid>,
    ) -> RepositoryFuture<'_, String>;
}
