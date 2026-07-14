use nazo_http_signatures::{
    RequestInput, RequestPolicy, SignatureFields, VerificationPolicy, VerifyError,
    parse_request_for_verification, prepare_request,
};

const CREATED: i64 = 1_720_000_000;
const BODY: &[u8] = br#"{"amount":10}"#;

fn headers() -> [(&'static str, &'static str); 3] {
    [
        ("Authorization", "DPoP opaque"),
        ("DPoP", "opaque-proof"),
        (
            "Content-Digest",
            "sha-256=:qLiLgv6QoWBI64hR/jgkBTlc05Xa+qfKm+kOwA+Cpys=:",
        ),
    ]
}

fn request<'a>(
    method: &'a str,
    target_uri: &'a str,
    headers: &'a [(&'a str, &'a str)],
    body: &'a [u8],
) -> RequestInput<'a> {
    RequestInput {
        method,
        target_uri,
        headers,
        body,
    }
}

fn policy() -> VerificationPolicy {
    VerificationPolicy {
        now: CREATED + 30,
        max_age_seconds: 60,
        future_skew_seconds: 5,
    }
}

fn fixture() -> (Vec<u8>, SignatureFields) {
    let headers = headers();
    let prepared = prepare_request(
        request("POST", "https://api.example/fapi/resource", &headers, BODY),
        RequestPolicy {
            created: CREATED,
            keyid: "client-ed25519",
            algorithm: "ed25519",
            covered_headers: &[],
        },
    )
    .unwrap();
    let base = prepared.signature_base().to_vec();
    (base, prepared.finish(&[0xde, 0xad, 0xbe, 0xef]))
}

fn parse(fields: SignatureFields) -> Result<nazo_http_signatures::VerifiedInput, VerifyError> {
    let headers = headers();
    parse_request_for_verification(
        request("POST", "https://api.example/fapi/resource", &headers, BODY),
        fields,
        policy(),
    )
}

#[test]
fn parses_a_valid_strict_request_signature() {
    let (base, fields) = fixture();
    let parsed = parse(fields).unwrap();

    assert_eq!(parsed.keyid(), "client-ed25519");
    assert_eq!(parsed.algorithm(), "ed25519");
    assert_eq!(parsed.created(), CREATED);
    assert_eq!(parsed.signature(), &[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(parsed.signature_base(), base);
    assert_eq!(parsed.replay_fingerprint().len(), 32);
}

#[test]
fn rejects_mismatched_labels() {
    let (_, mut fields) = fixture();
    fields.signature = fields.signature.replacen("sig1=", "other=", 1);
    assert_eq!(parse(fields).unwrap_err(), VerifyError::MissingSignature);
}

#[test]
fn rejects_missing_signature_label() {
    let (_, mut fields) = fixture();
    fields.signature.clear();
    assert_eq!(parse(fields).unwrap_err(), VerifyError::MissingSignature);
}

#[test]
fn rejects_multiple_signature_labels() {
    let (_, mut fields) = fixture();
    fields.signature_input = format!(
        "{}, sig2={}",
        fields.signature_input,
        fields.signature_input.strip_prefix("sig1=").unwrap()
    );
    fields.signature = format!("{}, sig2=:AQ==:", fields.signature);
    assert_eq!(parse(fields).unwrap_err(), VerifyError::AmbiguousSignature);
}

#[test]
fn rejects_a_duplicate_signature_label() {
    let (_, mut fields) = fixture();
    fields.signature = format!("{}, {}", fields.signature, fields.signature);
    assert_eq!(parse(fields).unwrap_err(), VerifyError::AmbiguousSignature);
}

#[test]
fn rejects_wrong_tag() {
    let (_, mut fields) = fixture();
    fields.signature_input = fields
        .signature_input
        .replace("tag=\"fapi-2-request\"", "tag=\"other\"");
    assert_eq!(parse(fields).unwrap_err(), VerifyError::InvalidTag);
}

fn remove_component(fields: &mut SignatureFields, component: &str) {
    fields.signature_input = fields
        .signature_input
        .replace(&format!("\"{component}\" "), "")
        .replace(&format!(" \"{component}\""), "");
}

#[test]
fn rejects_missing_method_coverage() {
    let (_, mut fields) = fixture();
    remove_component(&mut fields, "@method");
    assert_eq!(parse(fields).unwrap_err(), VerifyError::MissingComponent);
}

#[test]
fn rejects_missing_target_uri_coverage() {
    let (_, mut fields) = fixture();
    remove_component(&mut fields, "@target-uri");
    assert_eq!(parse(fields).unwrap_err(), VerifyError::MissingComponent);
}

#[test]
fn rejects_missing_authorization_coverage() {
    let (_, mut fields) = fixture();
    remove_component(&mut fields, "authorization");
    assert_eq!(parse(fields).unwrap_err(), VerifyError::MissingComponent);
}

#[test]
fn rejects_missing_dpop_coverage() {
    let (_, mut fields) = fixture();
    remove_component(&mut fields, "dpop");
    assert_eq!(parse(fields).unwrap_err(), VerifyError::MissingComponent);
}

#[test]
fn rejects_missing_digest_coverage() {
    let (_, mut fields) = fixture();
    remove_component(&mut fields, "content-digest");
    assert_eq!(parse(fields).unwrap_err(), VerifyError::MissingComponent);
}

#[test]
fn rejects_a_non_empty_body_without_an_actual_content_digest_header() {
    let (_, fields) = fixture();
    let no_digest = [("Authorization", "DPoP opaque"), ("DPoP", "opaque-proof")];
    assert_eq!(
        parse_request_for_verification(
            request(
                "POST",
                "https://api.example/fapi/resource",
                &no_digest,
                BODY,
            ),
            fields,
            policy(),
        )
        .unwrap_err(),
        VerifyError::DigestMismatch
    );
}

#[test]
fn rejects_stale_created_time() {
    let (_, fields) = fixture();
    assert_eq!(
        parse_request_for_verification(
            request(
                "POST",
                "https://api.example/fapi/resource",
                &headers(),
                BODY,
            ),
            fields,
            VerificationPolicy {
                now: CREATED + 61,
                ..policy()
            },
        )
        .unwrap_err(),
        VerifyError::InvalidCreated
    );
}

#[test]
fn rejects_created_too_far_in_the_future() {
    let (_, fields) = fixture();
    assert_eq!(
        parse_request_for_verification(
            request(
                "POST",
                "https://api.example/fapi/resource",
                &headers(),
                BODY,
            ),
            fields,
            VerificationPolicy {
                now: CREATED - 6,
                ..policy()
            },
        )
        .unwrap_err(),
        VerifyError::InvalidCreated
    );
}

#[test]
fn accepts_created_at_the_exact_max_age_boundary() {
    let (_, fields) = fixture();
    let parsed = parse_request_for_verification(
        request(
            "POST",
            "https://api.example/fapi/resource",
            &headers(),
            BODY,
        ),
        fields,
        VerificationPolicy {
            now: CREATED + 60,
            ..policy()
        },
    )
    .unwrap();
    assert_eq!(parsed.created(), CREATED);
}

#[test]
fn accepts_created_at_the_exact_future_skew_boundary() {
    let (_, fields) = fixture();
    let parsed = parse_request_for_verification(
        request(
            "POST",
            "https://api.example/fapi/resource",
            &headers(),
            BODY,
        ),
        fields,
        VerificationPolicy {
            now: CREATED - 5,
            ..policy()
        },
    )
    .unwrap();
    assert_eq!(parsed.created(), CREATED);
}

#[test]
fn rejects_expires_before_created() {
    let (_, mut fields) = fixture();
    fields.signature_input = fields.signature_input.replace(
        ";created=1720000000",
        ";created=1720000000;expires=1719999999",
    );
    assert_eq!(parse(fields).unwrap_err(), VerifyError::InvalidCreated);
}

#[test]
fn accepts_expires_at_the_exact_current_time_boundary() {
    let (_, mut fields) = fixture();
    fields.signature_input = fields.signature_input.replace(
        ";created=1720000000",
        ";created=1720000000;expires=1720000030",
    );
    assert!(parse(fields).is_ok());
}

#[test]
fn rejects_expires_one_second_before_current_time() {
    let (_, mut fields) = fixture();
    fields.signature_input = fields.signature_input.replace(
        ";created=1720000000",
        ";created=1720000000;expires=1720000029",
    );
    assert_eq!(parse(fields).unwrap_err(), VerifyError::InvalidCreated);
}

#[test]
fn rejects_a_duplicate_signature_parameter() {
    let (_, mut fields) = fixture();
    fields.signature_input = fields.signature_input.replace(
        ";created=1720000000",
        ";created=1720000000;created=1720000000",
    );
    assert_eq!(parse(fields).unwrap_err(), VerifyError::MalformedSignature);
}

#[test]
fn rejects_wrong_content_digest() {
    let (_, fields) = fixture();
    let wrong_headers = [
        ("Authorization", "DPoP opaque"),
        ("DPoP", "opaque-proof"),
        (
            "Content-Digest",
            "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:",
        ),
    ];
    assert_eq!(
        parse_request_for_verification(
            request(
                "POST",
                "https://api.example/fapi/resource",
                &wrong_headers,
                BODY,
            ),
            fields,
            policy(),
        )
        .unwrap_err(),
        VerifyError::DigestMismatch
    );
}

#[test]
fn accepts_an_rfc_9530_digest_dictionary_with_other_algorithms_and_ows() {
    let (_, fields) = fixture();
    let varied_headers = [
        ("Authorization", "DPoP opaque"),
        ("DPoP", "opaque-proof"),
        (
            "Content-Digest",
            "sha-512=:AA==: ,  sha-256=:qLiLgv6QoWBI64hR/jgkBTlc05Xa+qfKm+kOwA+Cpys=:",
        ),
    ];
    let parsed = parse_request_for_verification(
        request(
            "POST",
            "https://api.example/fapi/resource",
            &varied_headers,
            BODY,
        ),
        fields,
        policy(),
    )
    .unwrap();
    assert!(
        std::str::from_utf8(parsed.signature_base())
            .unwrap()
            .contains("sha-512=:AA==: ,  sha-256=:qLiLgv6Q")
    );
}

#[test]
fn rejects_duplicate_raw_sha_256_digest_members() {
    let (_, fields) = fixture();
    let duplicate_headers = [
        ("Authorization", "DPoP opaque"),
        ("DPoP", "opaque-proof"),
        (
            "Content-Digest",
            concat!(
                "sha-256=:qLiLgv6QoWBI64hR/jgkBTlc05Xa+qfKm+kOwA+Cpys=:, ",
                "sha-256=:qLiLgv6QoWBI64hR/jgkBTlc05Xa+qfKm+kOwA+Cpys=:"
            ),
        ),
    ];
    assert_eq!(
        parse_request_for_verification(
            request(
                "POST",
                "https://api.example/fapi/resource",
                &duplicate_headers,
                BODY,
            ),
            fields,
            policy(),
        )
        .unwrap_err(),
        VerifyError::DigestMismatch
    );
}

#[test]
fn rejects_a_sha_256_digest_member_with_the_wrong_sfv_type() {
    let (_, fields) = fixture();
    let wrong_type_headers = [
        ("Authorization", "DPoP opaque"),
        ("DPoP", "opaque-proof"),
        (
            "Content-Digest",
            "sha-256=\"qLiLgv6QoWBI64hR/jgkBTlc05Xa+qfKm+kOwA+Cpys=\"",
        ),
    ];
    assert_eq!(
        parse_request_for_verification(
            request(
                "POST",
                "https://api.example/fapi/resource",
                &wrong_type_headers,
                BODY,
            ),
            fields,
            policy(),
        )
        .unwrap_err(),
        VerifyError::DigestMismatch
    );
}

#[test]
fn rejects_a_sha_256_digest_that_is_not_exactly_32_bytes() {
    let (_, fields) = fixture();
    let short_digest_headers = [
        ("Authorization", "DPoP opaque"),
        ("DPoP", "opaque-proof"),
        ("Content-Digest", "sha-256=:AA==:"),
    ];
    assert_eq!(
        parse_request_for_verification(
            request(
                "POST",
                "https://api.example/fapi/resource",
                &short_digest_headers,
                BODY,
            ),
            fields,
            policy(),
        )
        .unwrap_err(),
        VerifyError::DigestMismatch
    );
}

#[test]
fn rejects_an_altered_body_without_a_matching_digest() {
    let (_, fields) = fixture();
    assert_eq!(
        parse_request_for_verification(
            request(
                "POST",
                "https://api.example/fapi/resource",
                &headers(),
                br#"{"amount":11}"#,
            ),
            fields,
            policy(),
        )
        .unwrap_err(),
        VerifyError::DigestMismatch
    );
}

fn assert_altered_base(method: &str, target_uri: &str, request_headers: &[(&str, &str)]) {
    let (base, fields) = fixture();
    let parsed = parse_request_for_verification(
        request(method, target_uri, request_headers, BODY),
        fields,
        policy(),
    )
    .unwrap();

    assert_ne!(parsed.signature_base(), base);
}

#[test]
fn reconstructs_a_different_base_for_an_altered_method() {
    assert_altered_base("PATCH", "https://api.example/fapi/resource", &headers());
}

#[test]
fn reconstructs_a_different_base_for_an_altered_target_uri() {
    assert_altered_base("POST", "https://api.example/fapi/other", &headers());
}

#[test]
fn reconstructs_a_different_base_for_an_altered_authorization() {
    let altered_headers = [
        ("Authorization", "DPoP altered"),
        ("DPoP", "opaque-proof"),
        headers()[2],
    ];
    assert_altered_base(
        "POST",
        "https://api.example/fapi/resource",
        &altered_headers,
    );
}

#[test]
fn reconstructs_a_different_base_for_an_altered_dpop_proof() {
    let altered_headers = [
        ("Authorization", "DPoP opaque"),
        ("DPoP", "altered-proof"),
        headers()[2],
    ];
    assert_altered_base(
        "POST",
        "https://api.example/fapi/resource",
        &altered_headers,
    );
}

#[test]
fn reconstructs_required_components_in_received_order() {
    let (_, mut fields) = fixture();
    fields.signature_input = fields.signature_input.replace(
        "(\"@method\" \"@target-uri\"",
        "(\"@target-uri\" \"@method\"",
    );
    let parsed = parse(fields).unwrap();
    let base = std::str::from_utf8(parsed.signature_base()).unwrap();
    assert!(
        base.starts_with("\"@target-uri\": https://api.example/fapi/resource\n\"@method\": POST")
    );
}

#[test]
fn rejects_duplicated_covered_components() {
    let (_, mut fields) = fixture();
    fields.signature_input = fields
        .signature_input
        .replace("(\"@method\"", "(\"@method\" \"@method\"");
    assert_eq!(parse(fields).unwrap_err(), VerifyError::MissingComponent);
}

#[test]
fn accepts_and_reconstructs_a_safe_extra_covered_header() {
    let (_, mut fields) = fixture();
    fields.signature_input = fields
        .signature_input
        .replace(" \"content-digest\")", " \"content-digest\" \"x-extra\")");
    let mut with_extra = headers().to_vec();
    with_extra.push(("X-Extra", "semantic-value"));
    let parsed = parse_request_for_verification(
        request(
            "POST",
            "https://api.example/fapi/resource",
            &with_extra,
            BODY,
        ),
        fields,
        policy(),
    )
    .unwrap();
    assert!(
        std::str::from_utf8(parsed.signature_base())
            .unwrap()
            .contains("\"x-extra\": semantic-value")
    );
}

#[test]
fn extra_header_tampering_reconstructs_a_different_base() {
    let (_, mut first_fields) = fixture();
    first_fields.signature_input = first_fields.signature_input.replace(
        " \"content-digest\")",
        " \"content-digest\" \"idempotency-key\")",
    );
    let second_fields = SignatureFields {
        signature_input: first_fields.signature_input.clone(),
        signature: first_fields.signature.clone(),
    };
    let first_headers = [headers().as_slice(), &[("Idempotency-Key", "first")]].concat();
    let second_headers = [headers().as_slice(), &[("Idempotency-Key", "second")]].concat();
    let first = parse_request_for_verification(
        request(
            "POST",
            "https://api.example/fapi/resource",
            &first_headers,
            BODY,
        ),
        first_fields,
        policy(),
    )
    .unwrap();
    let second = parse_request_for_verification(
        request(
            "POST",
            "https://api.example/fapi/resource",
            &second_headers,
            BODY,
        ),
        second_fields,
        policy(),
    )
    .unwrap();
    assert_ne!(first.signature_base(), second.signature_base());
}

#[test]
fn rejects_unsafe_or_ambiguous_extra_components() {
    for component in ["@authority", "x-missing", "authorization;foo"] {
        let (_, mut fields) = fixture();
        fields.signature_input = fields.signature_input.replace(
            " \"content-digest\")",
            &format!(" \"content-digest\" \"{component}\")"),
        );
        assert!(
            parse(fields).is_err(),
            "accepted unsafe component {component}"
        );
    }

    let (_, mut fields) = fixture();
    fields.signature_input = fields
        .signature_input
        .replace(" \"content-digest\")", " \"content-digest\" \"x-extra\")");
    let duplicate = [
        headers().as_slice(),
        &[("X-Extra", "one"), ("x-extra", "two")],
    ]
    .concat();
    assert_eq!(
        parse_request_for_verification(
            request(
                "POST",
                "https://api.example/fapi/resource",
                &duplicate,
                BODY,
            ),
            fields,
            policy(),
        )
        .unwrap_err(),
        VerifyError::MissingComponent
    );
}

#[test]
fn verifier_rejects_a_present_reserved_signature_extra() {
    let (_, mut fields) = fixture();
    fields.signature_input = fields
        .signature_input
        .replace(" \"content-digest\")", " \"content-digest\" \"signature\")");
    let with_reserved = [headers().as_slice(), &[("Signature", "sig2=:AQ==:")]].concat();
    assert_eq!(
        parse_request_for_verification(
            request(
                "POST",
                "https://api.example/fapi/resource",
                &with_reserved,
                BODY,
            ),
            fields,
            policy(),
        )
        .unwrap_err(),
        VerifyError::MissingComponent
    );
}

#[test]
fn rejects_duplicate_optional_profile_headers_even_when_not_covered() {
    let base_headers = [("Authorization", "DPoP opaque")];
    let prepared = prepare_request(
        request(
            "GET",
            "https://api.example/fapi/resource",
            &base_headers,
            b"",
        ),
        RequestPolicy {
            created: CREATED,
            keyid: "client-ed25519",
            algorithm: "ed25519",
            covered_headers: &[],
        },
    )
    .unwrap();
    let fields = prepared.finish(&[1, 2, 3]);
    let duplicate_dpop = [
        ("Authorization", "DPoP opaque"),
        ("DPoP", "first"),
        ("dpop", "second"),
    ];
    assert_eq!(
        parse_request_for_verification(
            request(
                "GET",
                "https://api.example/fapi/resource",
                &duplicate_dpop,
                b"",
            ),
            fields,
            policy(),
        )
        .unwrap_err(),
        VerifyError::MissingComponent
    );

    let prepared = prepare_request(
        request(
            "GET",
            "https://api.example/fapi/resource",
            &base_headers,
            b"",
        ),
        RequestPolicy {
            created: CREATED,
            keyid: "client-ed25519",
            algorithm: "ed25519",
            covered_headers: &[],
        },
    )
    .unwrap();
    let duplicate_digest = [
        ("Authorization", "DPoP opaque"),
        ("Content-Digest", "sha-256=:AA==:"),
        ("content-digest", "sha-256=:AQ==:"),
    ];
    assert_eq!(
        parse_request_for_verification(
            request(
                "GET",
                "https://api.example/fapi/resource",
                &duplicate_digest,
                b"",
            ),
            prepared.finish(&[1, 2, 3]),
            policy(),
        )
        .unwrap_err(),
        VerifyError::DigestMismatch
    );
}

#[test]
fn replay_fingerprint_changes_with_authenticated_request_context() {
    let (_, first_fields) = fixture();
    let first = parse(first_fields).unwrap();
    let (_, second_fields) = fixture();
    let altered_headers = [
        ("Authorization", "DPoP another-token"),
        ("DPoP", "opaque-proof"),
        headers()[2],
    ];
    let second = parse_request_for_verification(
        request(
            "POST",
            "https://api.example/fapi/resource",
            &altered_headers,
            BODY,
        ),
        second_fields,
        policy(),
    )
    .unwrap();

    assert_ne!(first.replay_fingerprint(), second.replay_fingerprint());
}

#[test]
fn preserves_custom_method_case_when_reconstructing_the_base() {
    let custom_headers = headers();
    let prepared = prepare_request(
        request(
            "m-search",
            "https://api.example/fapi/resource",
            &custom_headers,
            BODY,
        ),
        RequestPolicy {
            created: CREATED,
            keyid: "client-ed25519",
            algorithm: "ed25519",
            covered_headers: &[],
        },
    )
    .unwrap();
    let base = prepared.signature_base().to_vec();
    let fields = prepared.finish(&[1, 2, 3]);
    let parsed = parse_request_for_verification(
        request(
            "m-search",
            "https://api.example/fapi/resource",
            &custom_headers,
            BODY,
        ),
        fields,
        policy(),
    )
    .unwrap();

    assert_eq!(parsed.signature_base(), base);
}

#[test]
fn rejects_unknown_algorithm() {
    let (_, mut fields) = fixture();
    fields.signature_input = fields
        .signature_input
        .replace("alg=\"ed25519\"", "alg=\"hmac-sha256\"");
    assert_eq!(
        parse(fields).unwrap_err(),
        VerifyError::UnsupportedAlgorithm
    );
}

#[test]
fn verified_input_debug_output_is_fully_redacted() {
    let (_, fields) = fixture();
    let parsed = parse(fields).unwrap();
    let debug = format!("{parsed:?}");

    assert_eq!(debug, "VerifiedInput { .. }");
    for sensitive in [
        "client-ed25519",
        "opaque",
        "api.example",
        "222",
        "sha-256",
        "authorization",
    ] {
        assert!(!debug.contains(sensitive));
    }
}

#[test]
fn rejects_malformed_signature_input_structured_field() {
    let (_, mut fields) = fixture();
    fields.signature_input = "sig1=(\"@method\"".into();
    assert_eq!(parse(fields).unwrap_err(), VerifyError::MalformedSignature);
}

#[test]
fn rejects_malformed_signature_structured_field() {
    let (_, mut fields) = fixture();
    fields.signature = "sig1=:not base64!:".into();
    assert_eq!(parse(fields).unwrap_err(), VerifyError::MalformedSignature);
}

#[test]
fn rejects_target_uri_userinfo_and_non_ascii_covered_values() {
    let (_, fields) = fixture();
    assert_eq!(
        parse_request_for_verification(
            request(
                "POST",
                "https://user@api.example/fapi/resource",
                &headers(),
                BODY,
            ),
            fields,
            policy(),
        )
        .unwrap_err(),
        VerifyError::MissingComponent
    );

    let (_, fields) = fixture();
    let non_ascii = [
        ("Authorization", "DPoP opaqué"),
        ("DPoP", "opaque-proof"),
        headers()[2],
    ];
    assert_eq!(
        parse_request_for_verification(
            request(
                "POST",
                "https://api.example/fapi/resource",
                &non_ascii,
                BODY,
            ),
            fields,
            policy(),
        )
        .unwrap_err(),
        VerifyError::MissingComponent
    );
}
