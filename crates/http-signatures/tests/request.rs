use nazo_http_signatures::{
    RequestInput, RequestPolicy, content_digest, content_digest_field_matches, prepare_request,
};
use proptest::prelude::*;
use sfv::{BareItem, Dictionary, ListEntry, Parser};

#[test]
fn content_digest_encodes_sha256_as_a_structured_field_byte_sequence() {
    assert_eq!(
        content_digest(b"hello"),
        "sha-256=:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=:"
    );
}

#[test]
fn content_digest_semantics_accept_outer_ows_and_additional_digest_members() {
    let body = b"semantic digest body";
    let field = format!(" \t sha-512=:AA==:, {} \t", content_digest(body));

    assert!(content_digest_field_matches(&field, body));
    assert!(!content_digest_field_matches(
        &format!(
            "{}, sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:",
            content_digest(body)
        ),
        body
    ));
    assert!(!content_digest_field_matches(
        &content_digest(b"different"),
        body
    ));
}

#[test]
fn prepares_the_required_fapi_request_signature_components() {
    let headers = [("Authorization", "DPoP opaque"), ("DPoP", "opaque-proof")];
    let prepared = prepare_request(
        RequestInput {
            method: "POST",
            target_uri: "https://api.example/fapi/resource",
            headers: &headers,
            body: br#"{"amount":10}"#,
        },
        RequestPolicy {
            created: 1_720_000_000,
            keyid: "client-ed25519",
            algorithm: "ed25519",
            covered_headers: &[],
        },
    )
    .expect("valid request should be prepared");

    let expected_parameters = concat!(
        "(\"@method\" \"@target-uri\" \"authorization\" \"dpop\" \"content-digest\")",
        ";created=1720000000;keyid=\"client-ed25519\";alg=\"ed25519\";tag=\"fapi-2-request\""
    );
    let signature_base = std::str::from_utf8(prepared.signature_base()).unwrap();

    assert!(signature_base.contains("\"@method\": POST\n"));
    assert!(signature_base.contains("\"@target-uri\": https://api.example/fapi/resource\n"));
    assert!(signature_base.contains("\"authorization\": DPoP opaque\n"));
    assert!(signature_base.contains("\"dpop\": opaque-proof\n"));
    assert!(signature_base.contains("\"content-digest\": sha-256=:"));
    assert!(signature_base.ends_with(&format!("\"@signature-params\": {expected_parameters}")));

    let fields = prepared.finish(&[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(
        fields.signature_input,
        format!("sig1={expected_parameters}")
    );
    assert_eq!(fields.signature, "sig1=:3q2+7w==:");
}

#[test]
fn explicitly_covers_safe_additional_headers_in_caller_order() {
    let headers = [
        ("authorization", "DPoP opaque"),
        ("content-type", "application/json"),
        ("idempotency-key", "operation-123"),
    ];
    let prepared = prepare_request(
        RequestInput {
            method: "POST",
            target_uri: "https://api.example/fapi/resource",
            headers: &headers,
            body: b"",
        },
        RequestPolicy {
            created: 1_720_000_000,
            keyid: "key",
            algorithm: "ed25519",
            covered_headers: &["content-type", "idempotency-key"],
        },
    )
    .unwrap();
    let base = std::str::from_utf8(prepared.signature_base()).unwrap();

    assert!(base.contains(
        "\"authorization\": DPoP opaque\n\"content-type\": application/json\n\"idempotency-key\": operation-123"
    ));
    assert!(base.contains("\"authorization\" \"content-type\" \"idempotency-key\")"));
}

#[test]
fn rejects_reserved_signature_fields_as_additional_components() {
    for selected in ["signature", "Signature-Input"] {
        let headers = [
            ("authorization", "DPoP opaque"),
            ("signature", "sig1=:AQ==:"),
            ("signature-input", "sig1=(\"@method\")"),
        ];
        assert!(
            prepare_request(
                RequestInput {
                    method: "GET",
                    target_uri: "https://api.example/fapi/resource",
                    headers: &headers,
                    body: b"",
                },
                RequestPolicy {
                    created: 1_720_000_000,
                    keyid: "key",
                    algorithm: "ed25519",
                    covered_headers: &[selected],
                },
            )
            .is_err(),
            "accepted reserved field {selected}"
        );
    }
}

fn prepare<'a>(
    method: &'a str,
    target_uri: &'a str,
    headers: &'a [(&'a str, &'a str)],
    body: &'a [u8],
    keyid: &'a str,
    algorithm: &'a str,
) -> Result<nazo_http_signatures::PreparedSignature, nazo_http_signatures::RequestError> {
    prepare_request(
        RequestInput {
            method,
            target_uri,
            headers,
            body,
        },
        RequestPolicy {
            created: 1_720_000_000,
            keyid,
            algorithm,
            covered_headers: &[],
        },
    )
}

#[test]
fn rejects_invalid_method() {
    assert!(
        prepare(
            "PO ST",
            "https://api.example/fapi/resource",
            &[("authorization", "DPoP opaque")],
            b"",
            "key",
            "ed25519"
        )
        .is_err()
    );
}

#[test]
fn preserves_custom_method_case_in_the_signature_base() {
    let prepared = prepare(
        "m-search",
        "https://api.example/fapi/resource",
        &[("authorization", "DPoP opaque")],
        b"",
        "key",
        "ed25519",
    )
    .unwrap();
    let base = std::str::from_utf8(prepared.signature_base()).unwrap();

    assert!(base.contains("\"@method\": m-search\n"));
    assert!(!base.contains("\"@method\": M-SEARCH\n"));
}

#[test]
fn rejects_invalid_target_uri() {
    assert!(
        prepare(
            "GET",
            "/fapi/resource",
            &[("authorization", "DPoP opaque")],
            b"",
            "key",
            "ed25519"
        )
        .is_err()
    );
}

#[test]
fn rejects_target_uri_userinfo() {
    for target_uri in [
        "https://user@api.example/fapi/resource",
        "https://user:password@api.example/fapi/resource",
    ] {
        assert!(
            prepare(
                "GET",
                target_uri,
                &[("authorization", "DPoP opaque")],
                b"",
                "key",
                "ed25519"
            )
            .is_err(),
            "userinfo must be rejected in {target_uri}"
        );
    }
}

#[test]
fn rejects_target_uri_line_injection() {
    assert!(
        prepare(
            "GET",
            "https://api.example/fapi/resource\nx-evil: injected",
            &[("authorization", "DPoP opaque")],
            b"",
            "key",
            "ed25519"
        )
        .is_err()
    );
}

#[test]
fn signs_the_parsed_canonical_target_uri() {
    let prepared = prepare(
        "GET",
        "HTTPS://API.EXAMPLE:443/fapi/resource",
        &[("authorization", "DPoP opaque")],
        b"",
        "key",
        "ed25519",
    )
    .unwrap();
    let base = std::str::from_utf8(prepared.signature_base()).unwrap();

    assert!(base.contains("\"@target-uri\": https://api.example/fapi/resource\n"));
}

#[test]
fn rejects_missing_authorization() {
    assert!(
        prepare(
            "GET",
            "https://api.example/fapi/resource",
            &[],
            b"",
            "key",
            "ed25519"
        )
        .is_err()
    );
}

#[test]
fn rejects_header_injection() {
    assert!(
        prepare(
            "GET",
            "https://api.example/fapi/resource",
            &[("authorization", "DPoP opaque\r\nx-evil: injected")],
            b"",
            "key",
            "ed25519"
        )
        .is_err()
    );
}

#[test]
fn strips_outer_whitespace_from_covered_field_values() {
    let prepared = prepare(
        "GET",
        "https://api.example/fapi/resource",
        &[("authorization", " \tDPoP opaque\t ")],
        b"",
        "key",
        "ed25519",
    )
    .unwrap();
    let base = std::str::from_utf8(prepared.signature_base()).unwrap();

    assert!(base.contains("\"authorization\": DPoP opaque\n"));
    assert!(!base.contains("\"authorization\":  \t"));
}

#[test]
fn rejects_non_ascii_covered_field_values() {
    for headers in [
        [("authorization", "DPoP opaqué"), ("x-unused", "ascii")],
        [("authorization", "DPoP opaque"), ("dpop", "opaque-prööf")],
    ] {
        assert!(
            prepare(
                "GET",
                "https://api.example/fapi/resource",
                &headers,
                b"",
                "key",
                "ed25519"
            )
            .is_err()
        );
    }
}

#[test]
fn rejects_unsupported_algorithm() {
    for algorithm in [
        "not-a-signature-algorithm",
        "hmac-sha256",
        "ecdsa-p384-sha384",
    ] {
        assert!(
            prepare(
                "GET",
                "https://api.example/fapi/resource",
                &[("authorization", "DPoP opaque")],
                b"",
                "key",
                algorithm
            )
            .is_err(),
            "{algorithm} must not be accepted"
        );
    }
}

#[test]
fn accepts_the_profile_algorithm_allowlist() {
    for algorithm in ["ed25519", "rsa-v1_5-sha256", "ecdsa-p256-sha256"] {
        prepare(
            "GET",
            "https://api.example/fapi/resource",
            &[("authorization", "DPoP opaque")],
            b"",
            "key",
            algorithm,
        )
        .unwrap_or_else(|error| panic!("{algorithm} should be accepted: {error}"));
    }
}

#[test]
fn rejects_empty_key_id() {
    assert!(
        prepare(
            "GET",
            "https://api.example/fapi/resource",
            &[("authorization", "DPoP opaque")],
            b"",
            "",
            "ed25519"
        )
        .is_err()
    );
}

#[test]
fn rejects_duplicate_covered_headers() {
    let headers = [
        ("Authorization", "DPoP first"),
        ("authorization", "DPoP second"),
    ];
    assert!(
        prepare(
            "GET",
            "https://api.example/fapi/resource",
            &headers,
            b"",
            "key",
            "ed25519"
        )
        .is_err()
    );
}

#[test]
fn rejects_body_and_content_digest_conflict() {
    let headers = [
        ("authorization", "DPoP opaque"),
        (
            "content-digest",
            "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:",
        ),
    ];
    assert!(
        prepare(
            "POST",
            "https://api.example/fapi/resource",
            &headers,
            b"actual body",
            "key",
            "ed25519"
        )
        .is_err()
    );
}

#[test]
fn finish_encodes_arbitrary_signature_bytes_as_an_sfv_byte_sequence() {
    let prepared = prepare(
        "GET",
        "https://api.example/fapi/resource",
        &[("authorization", "DPoP opaque")],
        b"",
        "key",
        "ed25519",
    )
    .unwrap();
    let fields = prepared.finish(&[0x00, 0xff, b':', b',', b'"']);
    let dictionary: Dictionary = Parser::new(&fields.signature).parse().unwrap();

    match dictionary.get("sig1") {
        Some(ListEntry::Item(item)) => {
            assert_eq!(
                item.bare_item,
                BareItem::ByteSequence(vec![0x00, 0xff, b':', b',', b'"'])
            );
        }
        value => panic!("expected sig1 byte sequence, got {value:?}"),
    }
}

proptest! {
    #[test]
    fn digest_never_panics_for_arbitrary_bodies(body in proptest::collection::vec(any::<u8>(), 0..16_384)) {
        let digest = content_digest(&body);
        prop_assert!(digest.starts_with("sha-256=:"));
        prop_assert!(digest.ends_with(':'));
    }
}
