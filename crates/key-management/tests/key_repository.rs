use nazo_key_management::SigningKeyWrappingKeyRing;
use uuid::Uuid;

#[test]
fn encrypted_key_material_is_bound_to_its_tenant_and_purpose() {
    let ring = SigningKeyWrappingKeyRing::new(
        "current",
        [7_u8; 32],
        None,
    )
    .expect("test wrapping ring should be valid");
    let tenant = Uuid::now_v7();
    let sealed = ring
        .seal(tenant, "credential", b"private-key-material")
        .expect("material should seal");

    assert_eq!(
        ring.open(tenant, "credential", &sealed)
            .expect("matching scope should open"),
        b"private-key-material"
    );
    assert!(ring.open(Uuid::now_v7(), "credential", &sealed).is_err());
    assert!(ring.open(tenant, "presentation_request", &sealed).is_err());
}

#[test]
fn encrypted_generation_rejects_swapped_public_metadata() {
    let ring = SigningKeyWrappingKeyRing::new("current", [9_u8; 32], None).unwrap();
    let tenant = Uuid::now_v7();
    let metadata = serde_json::json!({"active_kid":"one","keys":[{"kid":"one"}]});
    let sealed = ring
        .seal_generation(tenant, 4, &metadata, b"private-generation")
        .unwrap();
    assert!(ring
        .open_generation(
            tenant,
            4,
            &serde_json::json!({"active_kid":"two","keys":[{"kid":"two"}]}),
            &sealed,
        )
        .is_err());
}
