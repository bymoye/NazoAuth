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
