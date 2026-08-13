#[path = "openid4vc_dataset.rs"]
mod dataset;
#[path = "openid4vc_issuance.rs"]
mod issuance;
#[path = "openid4vc_presentation.rs"]
mod presentation;

pub use dataset::{
    ManagedCredentialDataset, ManagedCredentialDatasetWrite, Openid4vciDatasetRepository,
};
pub(crate) use dataset::{
    insert_operator_conformance_dataset_on_connection, protect_dataset_claims,
    unprotect_dataset_claims,
};
pub use issuance::Openid4vciRepository;
pub use presentation::Openid4vpRepository;
