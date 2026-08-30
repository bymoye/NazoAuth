mod desired;
mod events;
mod instance;
mod mapping;
mod transaction;

use nazo_identity::ports::RepositoryError;
use nazo_runtime_modules::{
    CasOutcome, DesiredRevisionGuard, DesiredStateChange, DesiredStateRecord,
    InstanceStateMutation, InstanceStateRecord, ModuleEventPage, ModuleId, ModuleRevision,
    ModuleStateRepository,
};

use crate::DbPool;

pub type RuntimeModuleEventPage = ModuleEventPage;

#[derive(Clone)]
pub struct RuntimeModuleRepository {
    pool: DbPool,
}

impl RuntimeModuleRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub(super) async fn connection(&self) -> Result<crate::DbConnection, RepositoryError> {
        self.pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }

    pub async fn page_events(
        &self,
        offset: i64,
        limit: i64,
    ) -> Result<RuntimeModuleEventPage, RepositoryError> {
        events::page_events(self, offset, limit).await
    }
}

impl ModuleStateRepository for RuntimeModuleRepository {
    type Error = RepositoryError;

    async fn read_desired(
        &self,
        requested_module_id: ModuleId,
    ) -> Result<Option<DesiredStateRecord>, Self::Error> {
        desired::read_desired(self, requested_module_id).await
    }

    async fn read_all_desired(&self) -> Result<Vec<DesiredStateRecord>, Self::Error> {
        desired::read_all_desired(self).await
    }

    async fn compare_and_set_desired(
        &self,
        change: DesiredStateChange,
    ) -> Result<CasOutcome<DesiredStateRecord>, Self::Error> {
        desired::compare_and_set_desired(self, change, Vec::new()).await
    }

    async fn compare_and_set_desired_guarded(
        &self,
        change: DesiredStateChange,
        required_revisions: Vec<DesiredRevisionGuard>,
    ) -> Result<CasOutcome<DesiredStateRecord>, Self::Error> {
        desired::compare_and_set_desired(self, change, required_revisions).await
    }

    async fn read_instance(
        &self,
        requested_instance_id: &str,
        requested_module_id: ModuleId,
    ) -> Result<Option<InstanceStateRecord>, Self::Error> {
        instance::read_instance(self, requested_instance_id, requested_module_id).await
    }

    async fn read_all_instances(
        &self,
        requested_instance_id: &str,
    ) -> Result<Vec<InstanceStateRecord>, Self::Error> {
        instance::read_all_instances(self, requested_instance_id).await
    }

    async fn page_events(&self, offset: i64, limit: i64) -> Result<ModuleEventPage, Self::Error> {
        events::page_events(self, offset, limit).await
    }

    async fn compare_and_set_instance(
        &self,
        required_desired_revision: ModuleRevision,
        mutation: InstanceStateMutation,
    ) -> Result<CasOutcome<InstanceStateRecord>, Self::Error> {
        instance::compare_and_set_instance(self, required_desired_revision, mutation).await
    }

    async fn validate_revision(
        &self,
        requested_module_id: ModuleId,
        expected: ModuleRevision,
    ) -> Result<bool, Self::Error> {
        desired::validate_revision(self, requested_module_id, expected).await
    }
}

impl nazo_persistence::RuntimeModuleStore for RuntimeModuleRepository {
    fn read_desired(
        &self,
        module_id: ModuleId,
    ) -> futures_util::future::BoxFuture<'_, Result<Option<DesiredStateRecord>, RepositoryError>>
    {
        Box::pin(async move { desired::read_desired(self, module_id).await })
    }

    fn read_all_desired(
        &self,
    ) -> futures_util::future::BoxFuture<'_, Result<Vec<DesiredStateRecord>, RepositoryError>> {
        Box::pin(async move { desired::read_all_desired(self).await })
    }

    fn compare_and_set_desired(
        &self,
        change: DesiredStateChange,
    ) -> futures_util::future::BoxFuture<'_, Result<CasOutcome<DesiredStateRecord>, RepositoryError>>
    {
        Box::pin(async move { desired::compare_and_set_desired(self, change, Vec::new()).await })
    }

    fn compare_and_set_desired_guarded(
        &self,
        change: DesiredStateChange,
        required_revisions: Vec<DesiredRevisionGuard>,
    ) -> futures_util::future::BoxFuture<'_, Result<CasOutcome<DesiredStateRecord>, RepositoryError>>
    {
        Box::pin(
            async move { desired::compare_and_set_desired(self, change, required_revisions).await },
        )
    }

    fn read_instance<'a>(
        &'a self,
        instance_id: &'a str,
        module_id: ModuleId,
    ) -> futures_util::future::BoxFuture<'a, Result<Option<InstanceStateRecord>, RepositoryError>>
    {
        Box::pin(async move { instance::read_instance(self, instance_id, module_id).await })
    }

    fn read_all_instances<'a>(
        &'a self,
        instance_id: &'a str,
    ) -> futures_util::future::BoxFuture<'a, Result<Vec<InstanceStateRecord>, RepositoryError>>
    {
        Box::pin(async move { instance::read_all_instances(self, instance_id).await })
    }

    fn page_events(
        &self,
        offset: i64,
        limit: i64,
    ) -> futures_util::future::BoxFuture<'_, Result<ModuleEventPage, RepositoryError>> {
        Box::pin(async move { events::page_events(self, offset, limit).await })
    }

    fn compare_and_set_instance(
        &self,
        required_desired_revision: ModuleRevision,
        mutation: InstanceStateMutation,
    ) -> futures_util::future::BoxFuture<'_, Result<CasOutcome<InstanceStateRecord>, RepositoryError>>
    {
        Box::pin(async move {
            instance::compare_and_set_instance(self, required_desired_revision, mutation).await
        })
    }

    fn validate_revision(
        &self,
        module_id: ModuleId,
        expected: ModuleRevision,
    ) -> futures_util::future::BoxFuture<'_, Result<bool, RepositoryError>> {
        Box::pin(async move { desired::validate_revision(self, module_id, expected).await })
    }
}

// The focused unit test is intentionally mounted here so the production
// module remains the stable test boundary while implementation files evolve.
#[cfg(test)]
use desired::next_desired_revision;

#[cfg(test)]
#[path = "../../tests/unit/repositories/runtime_modules.rs"]
mod tests;
