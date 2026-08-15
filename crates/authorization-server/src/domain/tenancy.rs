#[cfg(test)]
pub(crate) use nazo_identity::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID};

#[cfg(test)]
#[path = "../../tests/unit/domain/tenancy.rs"]
mod tests;
