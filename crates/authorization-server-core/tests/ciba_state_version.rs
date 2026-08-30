use std::sync::Arc;

use nazo_auth::{CibaStateStorePort, CibaStateVersion};

fn assert_arc_port<T>()
where
    T: CibaStateStorePort + ?Sized,
    Arc<T>: CibaStateStorePort<Version = T::Version>,
{
}

#[test]
fn state_version_exposes_only_adapter_comparison_inputs() {
    let version = CibaStateVersion::new("opaque-snapshot".to_owned(), 1_700_000_120);

    assert_eq!(version.comparison_token(), "opaque-snapshot");
    assert_eq!(version.retention_expires_at(), 1_700_000_120);
}

#[test]
fn arc_trait_objects_preserve_the_store_version_type() {
    assert_arc_port::<dyn CibaStateStorePort<Version = CibaStateVersion>>();
}
