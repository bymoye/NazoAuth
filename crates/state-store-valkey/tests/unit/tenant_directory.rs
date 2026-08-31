use super::*;

fn snapshot(revision: u64) -> TenantDirectorySnapshot {
    TenantDirectorySnapshot {
        revision,
        tenants: vec![TenantDirectoryBinding {
            tenant: TenantContext {
                tenant_id: TenantId::new(Uuid::from_u128(1)).unwrap(),
                realm_id: RealmId::new(Uuid::from_u128(2)).unwrap(),
                organization_id: OrganizationId::new(Uuid::from_u128(3)).unwrap(),
            },
            runtime_revision: 1,
            issuer: "https://tenant.example.com".to_owned(),
            external_host: "tenant.example.com".to_owned(),
        }],
    }
}

#[test]
fn strict_round_trip_preserves_snapshot() {
    let expected = snapshot(7);
    let encoded = encode_snapshot(&expected).unwrap();
    assert_eq!(decode_snapshot(&encoded).unwrap(), expected);
}

#[test]
fn decoder_rejects_unknown_fields_and_noncanonical_revision() {
    let encoded = encode_snapshot(&snapshot(7)).unwrap();
    let with_unknown = encoded.replacen("{", r#"{"unknown":true,"#, 1);
    assert_eq!(
        decode_snapshot(&with_unknown).unwrap_err().kind(),
        crate::ErrorKind::CorruptData
    );
    assert_eq!(
        decode_snapshot(&encoded.replace(r#""revision":"7""#, r#""revision":"08""#))
            .unwrap_err()
            .kind(),
        crate::ErrorKind::CorruptData
    );
    assert_eq!(
        decode_snapshot(&encoded.replace(r#""runtime_revision":"1""#, r#""runtime_revision":"0""#))
            .unwrap_err()
            .kind(),
        crate::ErrorKind::CorruptData
    );
}
