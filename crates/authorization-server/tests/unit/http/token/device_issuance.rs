use super::*;

#[test]
fn device_grant_key_binds_code_and_sender_constraints_without_raw_material() {
    let bearer = device_grant_key("device-code", None, None);
    let dpop = device_grant_key("device-code", Some("dpop-jkt"), None);
    let mtls = device_grant_key("device-code", None, Some("mtls-thumbprint"));

    assert!(bearer.starts_with("device_code:"));
    assert!(!bearer.contains("device-code"));
    assert_ne!(bearer, dpop);
    assert_ne!(bearer, mtls);
    assert_ne!(dpop, mtls);
    assert_ne!(bearer, device_grant_key("other-device-code", None, None));
}
