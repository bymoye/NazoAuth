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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeDefaultPolicyMigration {
    pub previous_version: i32,
    pub current_version: i32,
    pub materialized_inherited_rows: usize,
    pub initialized_empty_state: bool,
}

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

    pub async fn migrate_composable_default_policy(
        &self,
        legacy_inherited_enabled: &std::collections::BTreeSet<ModuleId>,
    ) -> Result<RuntimeDefaultPolicyMigration, RepositoryError> {
        desired::migrate_composable_default_policy(self, legacy_inherited_enabled).await
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

// The focused unit test is intentionally mounted here so the production
// module remains the stable test boundary while implementation files evolve.
#[cfg(test)]
use desired::next_desired_revision;

#[cfg(test)]
#[path = "../../tests/unit/repositories/runtime_modules.rs"]
mod tests;
