use nazo_identity::TenantId;
use uuid::Uuid;

use super::{fapi_http_signature_replay, oidc_federation, private_key_jwt_replay};

fn tenant(value: u128) -> TenantId {
    TenantId::new(Uuid::from_u128(value)).expect("test tenant must be non-nil")
}

#[test]
fn fapi_http_signature_replay_key_is_tenant_scoped_and_stable() {
    let fingerprint = [0xa5; 32];
    let first_tenant = tenant(10);
    let first = fapi_http_signature_replay(first_tenant, &fingerprint);
    let same = fapi_http_signature_replay(first_tenant, &fingerprint);
    let other_tenant = fapi_http_signature_replay(tenant(11), &fingerprint);

    assert_eq!(first, same);
    assert!(first.starts_with(&format!(
        "fapi_http_signature_replay:{}:",
        first_tenant.as_uuid()
    )));
    assert_ne!(first, other_tenant);
}

#[test]
fn private_key_jwt_replay_key_is_client_scoped_and_hashed() {
    let first = private_key_jwt_replay("client-1", "assertion-jti");
    let same = private_key_jwt_replay("client-1", "assertion-jti");
    let other_client = private_key_jwt_replay("client-2", "assertion-jti");
    let other_jti = private_key_jwt_replay("client-1", "other-jti");

    assert_eq!(first, same);
    assert!(first.starts_with("oauth:client_assertion:jti:"));
    assert!(!first.contains("client-1"));
    assert!(!first.contains("assertion-jti"));
    assert_ne!(first, other_client);
    assert_ne!(first, other_jti);
}

#[test]
fn oidc_federation_state_key_is_deterministic_and_hides_the_state() {
    let first = oidc_federation("state-value");
    let same = oidc_federation("state-value");
    let other = oidc_federation("other-state");

    assert_eq!(first, same);
    assert!(first.starts_with("oauth:federation:oidc:state:"));
    assert!(!first.contains("state-value"));
    assert_ne!(first, other);
}
