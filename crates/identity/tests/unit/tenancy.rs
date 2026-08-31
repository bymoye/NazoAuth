use super::canonical_tenant_host;

#[test]
fn tenant_host_has_one_canonical_form() {
    assert_eq!(
        canonical_tenant_host(" Auth.Example. ").expect("DNS host should canonicalize"),
        "auth.example"
    );
    assert_eq!(
        canonical_tenant_host("[2001:db8::1]").expect("IPv6 host should canonicalize"),
        "[2001:db8::1]"
    );
    assert!(canonical_tenant_host("auth.example:443").is_err());
    assert!(canonical_tenant_host("https://auth.example").is_err());
}
