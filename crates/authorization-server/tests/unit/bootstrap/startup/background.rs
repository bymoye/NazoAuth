use super::*;
use crate::{
    bootstrap::{
        CibaPingDelivery, CibaPingDeliveryPort, CibaPingFinishOutcome, CibaPingFinishResult,
        TransientStateFuture,
    },
    config::ConfigSource,
};
use std::collections::BTreeSet;

struct EmptyDeliveries;

impl CibaPingDeliveryPort for EmptyDeliveries {
    fn claim_due(
        &self,
        _now: i64,
        _lock_until: i64,
        _limit: usize,
    ) -> TransientStateFuture<'_, Vec<CibaPingDelivery>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn finish<'a>(
        &'a self,
        _delivery: &'a CibaPingDelivery,
        _outcome: CibaPingFinishOutcome,
    ) -> TransientStateFuture<'a, CibaPingFinishResult> {
        Box::pin(async { Ok(CibaPingFinishResult::Missing) })
    }
}

#[tokio::test]
async fn worker_starts_when_ciba_is_disabled_in_startup_snapshot() {
    let settings = Settings::from_config(&ConfigSource::default()).expect("default settings load");
    let pool =
        nazo_postgres::create_pool("not a postgres url", 1).expect("a lazy test pool should build");
    let runtime_modules =
        crate::runtime_modules::test_support::runtime_modules_with_modules_for_test(
            pool,
            &settings,
            BTreeSet::new(),
        )
        .expect("disabled runtime-module snapshot should build");
    assert!(!nazo_auth::module_admissible(
        runtime_modules.registry.snapshot().as_ref(),
        nazo_runtime_modules::ModuleId::Ciba,
        nazo_auth::CapabilityAdmission::NewRequest,
    ));

    let worker = spawn_ciba_ping_worker(Arc::new(EmptyDeliveries), &settings, &runtime_modules)
        .expect("worker construction should succeed")
        .expect("CIBA delivery worker must not follow the startup module snapshot");
    worker.abort();
    assert!(
        worker
            .await
            .expect_err("aborted worker should stop")
            .is_cancelled()
    );
}
