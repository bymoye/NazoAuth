use super::*;

#[test]
fn fapi_http_signature_replay_key_contains_only_a_blake3_digest() {
    let raw_signature = b"raw-signature-secret";
    let authorization = b"DPoP raw-access-token-secret";
    let body = b"protected-body-secret";
    let fingerprint = blake3::hash(&[raw_signature.as_slice(), authorization, body].concat());

    let key = fapi_http_signature_replay_key(fingerprint.as_bytes());

    assert_eq!(
        key,
        format!("fapi_http_signature_replay:{}", fingerprint.to_hex())
    );
    assert!(!key.contains("raw-signature-secret"));
    assert!(!key.contains("raw-access-token-secret"));
    assert!(!key.contains("protected-body-secret"));
}

#[test]
fn valkey_key_builders_are_locked_to_the_reviewed_baseline() {
    for (fingerprint, expected) in [
        (
            [0x00; 32],
            "fapi_http_signature_replay:0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            [0xff; 32],
            "fapi_http_signature_replay:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
    ] {
        assert_eq!(fapi_http_signature_replay_key(&fingerprint), expected);
    }
}

#[test]
fn fapi_resource_http_signature_replay_accepts_only_exact_ok_reply() {
    assert_eq!(
        classify_fapi_http_signature_replay_reply(Some("OK")),
        ReplayConsumption::Accepted
    );
    assert_eq!(
        classify_fapi_http_signature_replay_reply(None),
        ReplayConsumption::Replay
    );
    for unexpected in ["ok", "1", "QUEUED", ""] {
        assert_eq!(
            classify_fapi_http_signature_replay_reply(Some(unexpected)),
            ReplayConsumption::DependencyFailure
        );
    }
}
