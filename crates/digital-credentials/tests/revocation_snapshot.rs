use std::sync::Arc;

use chrono::{Duration, Utc};
use nazo_digital_credentials::{
    CertificateRevocationEntry, CertificateRevocationPolicy, CertificateRevocationSnapshot,
    CertificateRevocationSnapshotError, CertificateRevocationStatus, CredentialTrustError,
    certificate_identity,
};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

const ISSUER: &str = "https://issuer.example";

fn certificate_der() -> Vec<u8> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("test P-256 key");
    CertificateParams::new(vec!["issuer.example".to_owned()])
        .expect("certificate params")
        .self_signed(&key)
        .expect("self-signed certificate")
        .der()
        .to_vec()
}

fn snapshot(
    certificate: &[u8],
    status: CertificateRevocationStatus,
) -> CertificateRevocationSnapshot {
    let now = Utc::now();
    CertificateRevocationSnapshot {
        version: CertificateRevocationSnapshot::VERSION,
        this_update: now - Duration::minutes(1),
        next_update: now + Duration::minutes(5),
        entries: vec![CertificateRevocationEntry {
            issuer: ISSUER.to_owned(),
            certificate: certificate_identity(certificate),
            status,
        }],
    }
}

#[test]
fn required_policy_accepts_an_explicit_good_status() {
    let certificate = certificate_der();
    let initial_snapshot = Arc::new(snapshot(&certificate, CertificateRevocationStatus::Good));

    CertificateRevocationPolicy::required(initial_snapshot)
        .check_chain(Some(ISSUER), &[certificate], Utc::now())
        .expect("fresh explicit good status is accepted");
}

#[test]
fn required_policy_rejects_a_revoked_certificate() {
    let certificate = certificate_der();
    let snapshot = Arc::new(snapshot(&certificate, CertificateRevocationStatus::Revoked));

    assert_eq!(
        CertificateRevocationPolicy::required(snapshot).check_chain(
            Some(ISSUER),
            &[certificate],
            Utc::now(),
        ),
        Err(CredentialTrustError::RevokedCertificate)
    );
}

#[test]
fn required_policy_rejects_mdoc_certificate_revocation_by_global_identity() {
    let certificate = certificate_der();
    let mut snapshot = snapshot(&certificate, CertificateRevocationStatus::Revoked);
    snapshot.entries[0].issuer = "x509:authority.example".to_owned();

    assert_eq!(
        CertificateRevocationPolicy::required(Arc::new(snapshot)).check_chain(
            None,
            &[certificate],
            Utc::now(),
        ),
        Err(CredentialTrustError::RevokedCertificate)
    );
}

#[test]
fn required_policy_rejects_an_unknown_issuer_or_certificate() {
    let certificate = certificate_der();
    let initial_snapshot = Arc::new(snapshot(&certificate, CertificateRevocationStatus::Good));

    assert_eq!(
        CertificateRevocationPolicy::required(initial_snapshot).check_chain(
            Some("https://other-issuer.example"),
            &[certificate],
            Utc::now(),
        ),
        Err(CredentialTrustError::RevocationStatusUnknown)
    );
}

#[test]
fn required_policy_accepts_unknown_certificate_only_for_lease_scoped_conformance_trust() {
    let certificate = certificate_der();
    let snapshot = Arc::new(snapshot(
        &certificate_der(),
        CertificateRevocationStatus::Good,
    ));

    CertificateRevocationPolicy::required(snapshot)
        .check_chain_with_conformance_trust(
            Some(ISSUER),
            &[certificate],
            Utc::now(),
            &[vec![1, 2, 3]],
        )
        .expect("an authenticated lease-scoped conformance chain may be absent from the operator snapshot");
}

#[test]
fn stale_snapshot_fails_closed_even_when_status_is_good() {
    let certificate = certificate_der();
    let mut snapshot = snapshot(&certificate, CertificateRevocationStatus::Good);
    snapshot.next_update = Utc::now() - Duration::seconds(1);

    assert_eq!(
        CertificateRevocationPolicy::required(Arc::new(snapshot)).check_chain(
            Some(ISSUER),
            &[certificate],
            Utc::now(),
        ),
        Err(CredentialTrustError::RevocationSnapshotStale)
    );
}

#[test]
fn optional_policy_allows_unknown_status_but_not_stale_snapshot() {
    let certificate = certificate_der();
    let initial_snapshot = Arc::new(snapshot(&certificate, CertificateRevocationStatus::Good));
    let other_certificate = certificate_der();
    CertificateRevocationPolicy::optional(initial_snapshot)
        .check_chain(Some(ISSUER), &[other_certificate], Utc::now())
        .expect("optional policy permits an unknown certificate while fresh");

    let mut stale = snapshot(&certificate, CertificateRevocationStatus::Good);
    stale.next_update = Utc::now() - Duration::seconds(1);
    assert_eq!(
        CertificateRevocationPolicy::optional(Arc::new(stale)).check_chain(
            Some(ISSUER),
            &[certificate],
            Utc::now(),
        ),
        Err(CredentialTrustError::RevocationSnapshotStale)
    );
}

#[test]
fn reload_publishes_revocation_and_rejects_a_failed_reload_without_overwriting_old_state() {
    let certificate = certificate_der();
    let old = Arc::new(snapshot(&certificate, CertificateRevocationStatus::Good));
    let policy = CertificateRevocationPolicy::required(old);

    let mut failed_reload = snapshot(&certificate, CertificateRevocationStatus::Revoked);
    let now = Utc::now();
    failed_reload.next_update = now - Duration::seconds(1);
    assert_eq!(
        policy.replace_snapshot(Arc::new(failed_reload), now),
        Err(CertificateRevocationSnapshotError::Expired)
    );
    policy
        .check_chain(Some(ISSUER), std::slice::from_ref(&certificate), now)
        .expect("failed reload must leave the fresh old snapshot installed");

    assert_eq!(
        policy.replace_snapshot_json(br#"{"#, now),
        Err(CertificateRevocationSnapshotError::InvalidEntry)
    );
    policy
        .check_chain(Some(ISSUER), std::slice::from_ref(&certificate), now)
        .expect("malformed reload must leave the fresh old snapshot installed");

    let replacement = Arc::new(snapshot(&certificate, CertificateRevocationStatus::Revoked));
    let replacement_now = Utc::now();
    policy
        .replace_snapshot(replacement, replacement_now)
        .expect("fresh replacement should publish atomically");
    assert_eq!(
        policy.check_chain(Some(ISSUER), &[certificate], replacement_now),
        Err(CredentialTrustError::RevokedCertificate)
    );
}

#[test]
fn json_snapshot_rejects_duplicate_issuer_certificate_entries() {
    let certificate = certificate_der();
    let now = Utc::now();
    let identity = certificate_identity(&certificate);
    let json = serde_json::json!({
        "version": 1,
        "this_update": now - Duration::minutes(1),
        "next_update": now + Duration::minutes(5),
        "entries": [
            {"issuer": ISSUER, "certificate": identity, "status": "good"},
            {"issuer": ISSUER, "certificate": identity, "status": "revoked"}
        ]
    });

    assert_eq!(
        CertificateRevocationSnapshot::from_json(
            serde_json::to_vec(&json).expect("snapshot JSON").as_slice(),
        ),
        Err(CertificateRevocationSnapshotError::DuplicateEntry)
    );
}

#[test]
fn snapshot_validation_rejects_unsupported_versions_and_invalid_intervals() {
    let certificate = certificate_der();
    let now = Utc::now();

    let mut unsupported = snapshot(&certificate, CertificateRevocationStatus::Good);
    unsupported.version = CertificateRevocationSnapshot::VERSION + 1;
    assert_eq!(
        unsupported.validate_structure(),
        Err(CertificateRevocationSnapshotError::UnsupportedVersion)
    );

    let mut invalid_interval = snapshot(&certificate, CertificateRevocationStatus::Good);
    invalid_interval.this_update = now;
    invalid_interval.next_update = now;
    assert_eq!(
        invalid_interval.validate_structure(),
        Err(CertificateRevocationSnapshotError::InvalidUpdateInterval)
    );
}

#[test]
fn snapshot_validation_rejects_invalid_entries_and_accepts_valid_json() {
    let certificate = certificate_der();

    let valid = snapshot(&certificate, CertificateRevocationStatus::Good);
    let encoded = serde_json::to_vec(&valid).expect("snapshot JSON");
    assert_eq!(
        CertificateRevocationSnapshot::from_json(&encoded).expect("valid snapshot JSON"),
        valid
    );

    let mut empty_issuer = valid.clone();
    empty_issuer.entries[0].issuer.clear();
    assert_eq!(
        empty_issuer.validate_structure(),
        Err(CertificateRevocationSnapshotError::InvalidEntry)
    );

    let mut oversized_issuer = valid.clone();
    oversized_issuer.entries[0].issuer = "i".repeat(2049);
    assert_eq!(
        oversized_issuer.validate_structure(),
        Err(CertificateRevocationSnapshotError::InvalidEntry)
    );

    let mut invalid_identity = valid.clone();
    invalid_identity.entries[0].certificate = "not-a-certificate-identity".to_owned();
    assert_eq!(
        invalid_identity.validate_structure(),
        Err(CertificateRevocationSnapshotError::InvalidEntry)
    );
}

#[test]
fn freshness_rejects_a_snapshot_that_is_not_yet_valid() {
    let certificate = certificate_der();
    let now = Utc::now();
    let mut future = snapshot(&certificate, CertificateRevocationStatus::Good);
    future.this_update = now + Duration::minutes(1);
    future.next_update = now + Duration::minutes(2);

    assert_eq!(
        future.validate_freshness_at(now),
        Err(CertificateRevocationSnapshotError::NotYetValid)
    );
}

#[test]
fn policy_modes_expose_snapshot_state_and_disabled_policy_fails_open() {
    let certificate = certificate_der();
    let now = Utc::now();

    let disabled = CertificateRevocationPolicy::default();
    assert!(!disabled.is_enabled());
    assert!(!disabled.is_required());
    assert!(disabled.snapshot().is_none());
    disabled
        .check_chain(Some(ISSUER), &[b"not a certificate".to_vec()], now)
        .expect("disabled policy does not inspect certificates");

    let required_without_snapshot = CertificateRevocationPolicy::required_without_snapshot();
    assert!(required_without_snapshot.is_enabled());
    assert!(required_without_snapshot.is_required());
    assert!(required_without_snapshot.snapshot().is_none());
    assert_eq!(
        required_without_snapshot.check_chain(None, &[], now),
        Err(CredentialTrustError::RevocationSnapshotUnavailable)
    );

    let optional = CertificateRevocationPolicy::optional(Arc::new(snapshot(
        &certificate,
        CertificateRevocationStatus::Good,
    )));
    assert!(optional.is_enabled());
    assert!(!optional.is_required());
    assert!(optional.snapshot().is_some());
}

#[test]
fn check_chain_maps_not_yet_valid_and_structurally_invalid_snapshots() {
    let certificate = certificate_der();
    let now = Utc::now();

    let mut future = snapshot(&certificate, CertificateRevocationStatus::Good);
    future.this_update = now + Duration::minutes(1);
    future.next_update = now + Duration::minutes(2);
    assert_eq!(
        CertificateRevocationPolicy::required(Arc::new(future)).check_chain(
            Some(ISSUER),
            std::slice::from_ref(&certificate),
            now,
        ),
        Err(CredentialTrustError::RevocationSnapshotStale)
    );

    let mut unsupported = snapshot(&certificate, CertificateRevocationStatus::Good);
    unsupported.version = CertificateRevocationSnapshot::VERSION + 1;
    assert_eq!(
        CertificateRevocationPolicy::required(Arc::new(unsupported)).check_chain(
            Some(ISSUER),
            &[certificate],
            now,
        ),
        Err(CredentialTrustError::RevocationSnapshotUnavailable)
    );
}

#[test]
fn global_certificate_status_requires_consistent_entries() {
    let certificate = certificate_der();
    let identity = certificate_identity(&certificate);

    let mut all_good = snapshot(&certificate, CertificateRevocationStatus::Good);
    all_good.entries.push(CertificateRevocationEntry {
        issuer: "x509:other-authority.example".to_owned(),
        certificate: identity.clone(),
        status: CertificateRevocationStatus::Good,
    });
    CertificateRevocationPolicy::required(Arc::new(all_good))
        .check_chain(None, std::slice::from_ref(&certificate), Utc::now())
        .expect("consistent global entries are good");

    let mut conflicting = snapshot(&certificate, CertificateRevocationStatus::Good);
    conflicting.entries.push(CertificateRevocationEntry {
        issuer: "x509:other-authority.example".to_owned(),
        certificate: identity,
        status: CertificateRevocationStatus::Revoked,
    });
    assert_eq!(
        CertificateRevocationPolicy::required(Arc::new(conflicting)).check_chain(
            None,
            std::slice::from_ref(&certificate),
            Utc::now(),
        ),
        Err(CredentialTrustError::RevocationStatusUnknown)
    );
}
