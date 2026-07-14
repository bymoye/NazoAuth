use nazo_http_signatures::{
    OriginalRequest, RequestInput, ResponseInput, ResponsePolicy, SignatureFields,
    VerificationPolicy, VerifyError, content_digest, parse_response_for_verification,
    prepare_response,
};

const CREATED: i64 = 1_720_000_000;
const REQUEST_BODY: &[u8] = br#"{"amount":10}"#;
const RESPONSE_BODY: &[u8] = br#"{"approved":true}"#;

fn request_headers(body: &[u8]) -> Vec<(&'static str, String)> {
    vec![
        ("Authorization", "DPoP opaque".into()),
        ("Content-Digest", content_digest(body)),
    ]
}

fn response_headers(body: &[u8]) -> Vec<(&'static str, String)> {
    vec![("Content-Digest", content_digest(body))]
}

fn borrowed<'a>(headers: &'a [(&'static str, String)]) -> Vec<(&'a str, &'a str)> {
    headers
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect()
}

fn request_fields() -> SignatureFields {
    SignatureFields {
        signature_input: concat!(
            "sig1=(\"@method\" \"@target-uri\" \"authorization\" \"content-digest\")",
            ";created=1720000000;keyid=\"client\";alg=\"ed25519\";tag=\"fapi-2-request\""
        )
        .into(),
        signature: "sig1=:3q2+7w==:".into(),
    }
}

fn verification_policy() -> VerificationPolicy {
    VerificationPolicy {
        now: CREATED + 30,
        max_age_seconds: 60,
        future_skew_seconds: 5,
    }
}

#[test]
fn prepares_response_signature_with_exact_request_linkage() {
    let request_headers = request_headers(REQUEST_BODY);
    let request_headers = borrowed(&request_headers);
    let response_headers = response_headers(RESPONSE_BODY);
    let response_headers = borrowed(&response_headers);
    let fields = request_fields();

    let prepared = prepare_response(
        ResponseInput {
            status: 200,
            headers: &response_headers,
            body: RESPONSE_BODY,
        },
        OriginalRequest {
            input: RequestInput {
                method: "POST",
                target_uri: "https://api.example/fapi/resource",
                headers: &request_headers,
                body: REQUEST_BODY,
            },
            signature_fields: Some(&fields),
        },
        ResponsePolicy {
            created: CREATED,
            keyid: "server-ed25519",
            algorithm: "ed25519",
            covered_headers: &[],
            covered_request_headers: &[],
        },
    )
    .unwrap();

    let response_digest = content_digest(RESPONSE_BODY);
    let request_digest = content_digest(REQUEST_BODY);
    let expected = format!(
        concat!(
            "\"@status\": 200\n",
            "\"content-digest\": {response_digest}\n",
            "\"@method\";req: POST\n",
            "\"@target-uri\";req: https://api.example/fapi/resource\n",
            "\"content-digest\";req: {request_digest}\n",
            "\"signature-input\";req: {request_signature_input}\n",
            "\"signature\";req: {request_signature}\n",
            "\"@signature-params\": (\"@status\" \"content-digest\" ",
            "\"@method\";req \"@target-uri\";req \"content-digest\";req ",
            "\"signature-input\";req \"signature\";req);created=1720000000;",
            "keyid=\"server-ed25519\";alg=\"ed25519\";tag=\"fapi-2-response\""
        ),
        response_digest = response_digest,
        request_digest = request_digest,
        request_signature_input = fields.signature_input,
        request_signature = fields.signature,
    );
    assert_eq!(prepared.signature_base(), expected.as_bytes());

    let finished = prepared.finish(&[0xde, 0xad, 0xbe, 0xef]);
    assert!(finished.signature_input.starts_with("nazo=("));
    assert_eq!(finished.signature, "nazo=:3q2+7w==:");
}

#[test]
fn response_extra_components_round_trip_from_their_exact_contexts() {
    let response_digest = content_digest(RESPONSE_BODY);
    let response_headers = [
        ("Content-Digest", response_digest.as_str()),
        ("Content-Type", "application/json"),
        ("X-Fapi-Interaction-Id", "interaction-123"),
    ];
    let request_digest = content_digest(REQUEST_BODY);
    let request_headers = [
        ("Authorization", "DPoP opaque"),
        ("Content-Digest", request_digest.as_str()),
        ("Idempotency-Key", "operation-123"),
    ];
    let request_fields = request_fields();
    let prepared = prepare_response(
        ResponseInput {
            status: 200,
            headers: &response_headers,
            body: RESPONSE_BODY,
        },
        OriginalRequest {
            input: RequestInput {
                method: "POST",
                target_uri: "https://api.example/fapi/resource",
                headers: &request_headers,
                body: REQUEST_BODY,
            },
            signature_fields: Some(&request_fields),
        },
        ResponsePolicy {
            created: CREATED,
            keyid: "server-ed25519",
            algorithm: "ed25519",
            covered_headers: &["content-type", "x-fapi-interaction-id"],
            covered_request_headers: &["idempotency-key"],
        },
    )
    .unwrap();
    let expected = prepared.signature_base().to_vec();
    let fields = prepared.finish(&[1, 2, 3]);
    let parsed = parse_response_for_verification(
        ResponseInput {
            status: 200,
            headers: &response_headers,
            body: RESPONSE_BODY,
        },
        OriginalRequest {
            input: RequestInput {
                method: "POST",
                target_uri: "https://api.example/fapi/resource",
                headers: &request_headers,
                body: REQUEST_BODY,
            },
            signature_fields: Some(&request_fields),
        },
        fields,
        verification_policy(),
    )
    .unwrap();
    let base = std::str::from_utf8(parsed.signature_base()).unwrap();

    assert_eq!(parsed.signature_base(), expected);
    assert!(base.contains("\"content-type\": application/json"));
    assert!(base.contains("\"x-fapi-interaction-id\": interaction-123"));
    assert!(base.contains("\"idempotency-key\";req: operation-123"));
}

#[test]
fn response_signing_rejects_reserved_signature_fields_as_explicit_extras() {
    for (response_selected, request_selected) in [
        (&["Signature"][..], &[][..]),
        (&["signature-input"][..], &[][..]),
        (&[][..], &["Signature"][..]),
        (&[][..], &["signature-input"][..]),
    ] {
        let response_headers = [
            ("signature", "nazo=:AQ==:"),
            ("signature-input", "nazo=(\"@status\")"),
        ];
        let request_headers = [
            ("signature", "sig1=:AQ==:"),
            ("signature-input", "sig1=(\"@method\")"),
        ];
        assert!(
            prepare_response(
                ResponseInput {
                    status: 204,
                    headers: &response_headers,
                    body: b"",
                },
                OriginalRequest {
                    input: RequestInput {
                        method: "GET",
                        target_uri: "https://api.example/fapi/resource",
                        headers: &request_headers,
                        body: b"",
                    },
                    signature_fields: None,
                },
                ResponsePolicy {
                    created: CREATED,
                    keyid: "server-ed25519",
                    algorithm: "ed25519",
                    covered_headers: response_selected,
                    covered_request_headers: request_selected,
                },
            )
            .is_err()
        );
    }
}

#[test]
fn response_signing_requires_a_physical_content_digest_for_a_non_empty_body() {
    let request_headers = request_headers(REQUEST_BODY);
    let request_headers = borrowed(&request_headers);
    let fields = request_fields();
    let result = prepare_response(
        ResponseInput {
            status: 200,
            headers: &[],
            body: RESPONSE_BODY,
        },
        OriginalRequest {
            input: RequestInput {
                method: "POST",
                target_uri: "https://api.example/fapi/resource",
                headers: &request_headers,
                body: REQUEST_BODY,
            },
            signature_fields: Some(&fields),
        },
        ResponsePolicy {
            created: CREATED,
            keyid: "server-ed25519",
            algorithm: "ed25519",
            covered_headers: &[],
            covered_request_headers: &[],
        },
    );

    assert!(result.is_err());
}

#[test]
fn response_signing_accepts_and_preserves_valid_multi_algorithm_digest_serialization() {
    let request_headers = request_headers(REQUEST_BODY);
    let request_headers = borrowed(&request_headers);
    let fields = request_fields();
    let varied_digest = format!("  sha-512=:AA==: ,  {}  ", content_digest(RESPONSE_BODY));
    let response_headers = [("Content-Digest", varied_digest.as_str())];
    let prepared = prepare_response(
        ResponseInput {
            status: 200,
            headers: &response_headers,
            body: RESPONSE_BODY,
        },
        OriginalRequest {
            input: RequestInput {
                method: "POST",
                target_uri: "https://api.example/fapi/resource",
                headers: &request_headers,
                body: REQUEST_BODY,
            },
            signature_fields: Some(&fields),
        },
        ResponsePolicy {
            created: CREATED,
            keyid: "server-ed25519",
            algorithm: "ed25519",
            covered_headers: &[],
            covered_request_headers: &[],
        },
    )
    .unwrap();

    let base = std::str::from_utf8(prepared.signature_base()).unwrap();
    assert!(base.contains(&format!("\"content-digest\": {}", varied_digest.trim())));
}

#[test]
fn response_signing_rejects_invalid_physical_digest_fields() {
    let correct = content_digest(RESPONSE_BODY);
    let invalid = [
        format!("{correct}, {correct}"),
        format!("{correct}, bogus=\"not-a-digest\""),
        "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:".into(),
    ];
    for digest in invalid {
        let request_headers = request_headers(REQUEST_BODY);
        let request_headers = borrowed(&request_headers);
        let fields = request_fields();
        let response_headers = [("Content-Digest", digest.as_str())];
        let result = prepare_response(
            ResponseInput {
                status: 200,
                headers: &response_headers,
                body: RESPONSE_BODY,
            },
            OriginalRequest {
                input: RequestInput {
                    method: "POST",
                    target_uri: "https://api.example/fapi/resource",
                    headers: &request_headers,
                    body: REQUEST_BODY,
                },
                signature_fields: Some(&fields),
            },
            ResponsePolicy {
                created: CREATED,
                keyid: "server-ed25519",
                algorithm: "ed25519",
                covered_headers: &[],
                covered_request_headers: &[],
            },
        );
        assert!(result.is_err(), "invalid digest accepted: {digest}");
    }
}

#[test]
fn request_req_digest_requires_a_physical_strict_digest_field() {
    let response_headers = response_headers(RESPONSE_BODY);
    let response_headers = borrowed(&response_headers);
    let fields = request_fields();
    let missing = [("Authorization", "DPoP opaque")];
    let correct = content_digest(REQUEST_BODY);
    let invalid = [
        format!("{correct}, {correct}"),
        format!("{correct}, bogus=\"not-a-digest\""),
        "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:".into(),
    ];
    let missing_result = prepare_response(
        ResponseInput {
            status: 200,
            headers: &response_headers,
            body: RESPONSE_BODY,
        },
        OriginalRequest {
            input: RequestInput {
                method: "POST",
                target_uri: "https://api.example/fapi/resource",
                headers: &missing,
                body: REQUEST_BODY,
            },
            signature_fields: Some(&fields),
        },
        ResponsePolicy {
            created: CREATED,
            keyid: "server-ed25519",
            algorithm: "ed25519",
            covered_headers: &[],
            covered_request_headers: &[],
        },
    );
    assert!(missing_result.is_err());

    for digest in invalid {
        let invalid_headers = [
            ("Authorization", "DPoP opaque"),
            ("Content-Digest", digest.as_str()),
        ];
        let result = prepare_response(
            ResponseInput {
                status: 200,
                headers: &response_headers,
                body: RESPONSE_BODY,
            },
            OriginalRequest {
                input: RequestInput {
                    method: "POST",
                    target_uri: "https://api.example/fapi/resource",
                    headers: &invalid_headers,
                    body: REQUEST_BODY,
                },
                signature_fields: Some(&fields),
            },
            ResponsePolicy {
                created: CREATED,
                keyid: "server-ed25519",
                algorithm: "ed25519",
                covered_headers: &[],
                covered_request_headers: &[],
            },
        );
        assert!(result.is_err(), "invalid request digest accepted: {digest}");
    }
}

#[test]
fn request_req_digest_accepts_and_preserves_valid_multi_algorithm_serialization() {
    let response_headers = response_headers(RESPONSE_BODY);
    let response_headers = borrowed(&response_headers);
    let varied_digest = format!("  sha-512=:AA==: ,  {}  ", content_digest(REQUEST_BODY));
    let request_headers = [
        ("Authorization", "DPoP opaque"),
        ("Content-Digest", varied_digest.as_str()),
    ];
    let fields = request_fields();
    let prepared = prepare_response(
        ResponseInput {
            status: 200,
            headers: &response_headers,
            body: RESPONSE_BODY,
        },
        OriginalRequest {
            input: RequestInput {
                method: "POST",
                target_uri: "https://api.example/fapi/resource",
                headers: &request_headers,
                body: REQUEST_BODY,
            },
            signature_fields: Some(&fields),
        },
        ResponsePolicy {
            created: CREATED,
            keyid: "server-ed25519",
            algorithm: "ed25519",
            covered_headers: &[],
            covered_request_headers: &[],
        },
    )
    .unwrap();

    let base = std::str::from_utf8(prepared.signature_base()).unwrap();
    assert!(base.contains(&format!("\"content-digest\";req: {}", varied_digest.trim())));
}

#[test]
fn unrelated_obs_text_headers_do_not_affect_response_signing() {
    let request_digest = content_digest(REQUEST_BODY);
    let request_headers = [
        ("Authorization", "DPoP opaque"),
        ("Content-Digest", request_digest.as_str()),
        ("X-Uncovered-Request", "opaque-é"),
    ];
    let response_digest = content_digest(RESPONSE_BODY);
    let response_headers = [
        ("Content-Digest", response_digest.as_str()),
        ("X-Uncovered-Response", "opaque-é"),
    ];
    let fields = request_fields();

    assert!(
        prepare_response(
            ResponseInput {
                status: 200,
                headers: &response_headers,
                body: RESPONSE_BODY,
            },
            OriginalRequest {
                input: RequestInput {
                    method: "POST",
                    target_uri: "https://api.example/fapi/resource",
                    headers: &request_headers,
                    body: REQUEST_BODY,
                },
                signature_fields: Some(&fields),
            },
            ResponsePolicy {
                created: CREATED,
                keyid: "server-ed25519",
                algorithm: "ed25519",
                covered_headers: &[],
                covered_request_headers: &[],
            },
        )
        .is_ok()
    );
}

#[test]
fn covered_request_signature_fields_still_reject_non_ascii_values() {
    let request_headers = request_headers(REQUEST_BODY);
    let request_headers = borrowed(&request_headers);
    let response_headers = response_headers(RESPONSE_BODY);
    let response_headers = borrowed(&response_headers);
    let mut fields = request_fields();
    fields.signature = "sig1=:AQID:é".into();

    assert!(
        prepare_response(
            ResponseInput {
                status: 200,
                headers: &response_headers,
                body: RESPONSE_BODY,
            },
            OriginalRequest {
                input: RequestInput {
                    method: "POST",
                    target_uri: "https://api.example/fapi/resource",
                    headers: &request_headers,
                    body: REQUEST_BODY,
                },
                signature_fields: Some(&fields),
            },
            ResponsePolicy {
                created: CREATED,
                keyid: "server-ed25519",
                algorithm: "ed25519",
                covered_headers: &[],
                covered_request_headers: &[],
            },
        )
        .is_err()
    );
}

struct Fixture {
    base: Vec<u8>,
    response_fields: SignatureFields,
    request_fields: SignatureFields,
}

fn fixture() -> Fixture {
    let request_headers = request_headers(REQUEST_BODY);
    let borrowed_request_headers = borrowed(&request_headers);
    let response_headers = response_headers(RESPONSE_BODY);
    let borrowed_response_headers = borrowed(&response_headers);
    let request_fields = request_fields();
    let prepared = prepare_response(
        ResponseInput {
            status: 200,
            headers: &borrowed_response_headers,
            body: RESPONSE_BODY,
        },
        OriginalRequest {
            input: RequestInput {
                method: "POST",
                target_uri: "https://api.example/fapi/resource",
                headers: &borrowed_request_headers,
                body: REQUEST_BODY,
            },
            signature_fields: Some(&request_fields),
        },
        ResponsePolicy {
            created: CREATED,
            keyid: "server-ed25519",
            algorithm: "ed25519",
            covered_headers: &[],
            covered_request_headers: &[],
        },
    )
    .unwrap();
    let base = prepared.signature_base().to_vec();
    Fixture {
        base,
        response_fields: prepared.finish(&[1, 2, 3, 4]),
        request_fields,
    }
}

#[allow(clippy::too_many_arguments)]
fn parse(
    status: u16,
    response_body: &[u8],
    response_headers: &[(&str, &str)],
    method: &str,
    target_uri: &str,
    request_body: &[u8],
    request_headers: &[(&str, &str)],
    request_fields: &SignatureFields,
    response_fields: SignatureFields,
) -> Result<nazo_http_signatures::VerifiedInput, VerifyError> {
    parse_response_for_verification(
        ResponseInput {
            status,
            headers: response_headers,
            body: response_body,
        },
        OriginalRequest {
            input: RequestInput {
                method,
                target_uri,
                headers: request_headers,
                body: request_body,
            },
            signature_fields: Some(request_fields),
        },
        response_fields,
        verification_policy(),
    )
}

#[test]
fn client_reconstructs_exact_response_signature_base() {
    let fixture = fixture();
    let request_headers = request_headers(REQUEST_BODY);
    let request_headers = borrowed(&request_headers);
    let response_headers = response_headers(RESPONSE_BODY);
    let response_headers = borrowed(&response_headers);
    let parsed = parse(
        200,
        RESPONSE_BODY,
        &response_headers,
        "POST",
        "https://api.example/fapi/resource",
        REQUEST_BODY,
        &request_headers,
        &fixture.request_fields,
        fixture.response_fields,
    )
    .unwrap();

    assert_eq!(parsed.signature_base(), fixture.base);
    assert_eq!(parsed.signature(), &[1, 2, 3, 4]);
    assert_eq!(parsed.keyid(), "server-ed25519");
    assert_eq!(parsed.algorithm(), "ed25519");
    assert_eq!(parsed.created(), CREATED);
}

#[test]
fn response_verifier_reconstructs_required_components_in_received_order() {
    let mut fixture = fixture();
    fixture.response_fields.signature_input = fixture.response_fields.signature_input.replace(
        "(\"@status\" \"content-digest\"",
        "(\"content-digest\" \"@status\"",
    );
    let request_headers = request_headers(REQUEST_BODY);
    let request_headers = borrowed(&request_headers);
    let response_headers = response_headers(RESPONSE_BODY);
    let response_headers = borrowed(&response_headers);
    let parsed = parse(
        200,
        RESPONSE_BODY,
        &response_headers,
        "POST",
        "https://api.example/fapi/resource",
        REQUEST_BODY,
        &request_headers,
        &fixture.request_fields,
        fixture.response_fields,
    )
    .unwrap();
    assert!(
        std::str::from_utf8(parsed.signature_base())
            .unwrap()
            .starts_with("\"content-digest\": sha-256=:")
    );
}

#[test]
fn response_extra_header_tampering_reconstructs_a_different_base() {
    let request_headers = request_headers(REQUEST_BODY);
    let request_headers = borrowed(&request_headers);
    let digest = content_digest(RESPONSE_BODY);
    let first_headers = [
        ("Content-Digest", digest.as_str()),
        ("Content-Type", "application/json"),
    ];
    let second_headers = [
        ("Content-Digest", digest.as_str()),
        ("Content-Type", "text/plain"),
    ];
    let mut first = fixture();
    first.response_fields.signature_input = first.response_fields.signature_input.replace(
        "\"content-digest\" ",
        "\"content-digest\" \"content-type\" ",
    );
    let mut second = fixture();
    second.response_fields.signature_input = first.response_fields.signature_input.clone();
    let first_parsed = parse(
        200,
        RESPONSE_BODY,
        &first_headers,
        "POST",
        "https://api.example/fapi/resource",
        REQUEST_BODY,
        &request_headers,
        &first.request_fields,
        first.response_fields,
    )
    .unwrap();
    let second_parsed = parse(
        200,
        RESPONSE_BODY,
        &second_headers,
        "POST",
        "https://api.example/fapi/resource",
        REQUEST_BODY,
        &request_headers,
        &second.request_fields,
        second.response_fields,
    )
    .unwrap();
    assert_ne!(
        first_parsed.signature_base(),
        second_parsed.signature_base()
    );
}

#[test]
fn response_verifier_rejects_unsafe_or_ambiguous_extra_components() {
    for item in ["\"@authority\"", "\"x-missing\"", "\"content-type\";foo"] {
        let mut fixture = fixture();
        fixture.response_fields.signature_input = fixture.response_fields.signature_input.replace(
            "\"content-digest\" ",
            &format!("\"content-digest\" {item} "),
        );
        let request_headers = request_headers(REQUEST_BODY);
        let request_headers = borrowed(&request_headers);
        let response_headers = response_headers(RESPONSE_BODY);
        let response_headers = borrowed(&response_headers);
        assert!(
            parse(
                200,
                RESPONSE_BODY,
                &response_headers,
                "POST",
                "https://api.example/fapi/resource",
                REQUEST_BODY,
                &request_headers,
                &fixture.request_fields,
                fixture.response_fields,
            )
            .is_err(),
            "unsafe item accepted: {item}"
        );
    }
}

#[test]
fn response_verifier_rejects_a_present_reserved_response_signature_extra() {
    let mut fixture = fixture();
    fixture.response_fields.signature_input = fixture
        .response_fields
        .signature_input
        .replace("\"content-digest\" ", "\"content-digest\" \"signature\" ");
    let request_headers = request_headers(REQUEST_BODY);
    let request_headers = borrowed(&request_headers);
    let digest = content_digest(RESPONSE_BODY);
    let response_headers = [
        ("Content-Digest", digest.as_str()),
        ("Signature", "nazo=:AQ==:"),
    ];
    assert_eq!(
        parse(
            200,
            RESPONSE_BODY,
            &response_headers,
            "POST",
            "https://api.example/fapi/resource",
            REQUEST_BODY,
            &request_headers,
            &fixture.request_fields,
            fixture.response_fields,
        )
        .unwrap_err(),
        VerifyError::MissingComponent
    );
}

#[test]
fn authenticated_context_changes_reconstruct_a_different_base() {
    for change in [
        "status",
        "uri",
        "request-signature-input",
        "request-signature",
    ] {
        let fixture = fixture();
        let request_headers = request_headers(REQUEST_BODY);
        let request_headers = borrowed(&request_headers);
        let response_headers = response_headers(RESPONSE_BODY);
        let response_headers = borrowed(&response_headers);
        let altered_request_fields = SignatureFields {
            signature_input: if change == "request-signature-input" {
                fixture
                    .request_fields
                    .signature_input
                    .replace("keyid=\"client\"", "keyid=\"other-client\"")
            } else {
                fixture.request_fields.signature_input.clone()
            },
            signature: if change == "request-signature" {
                "sig1=:AQIDBA==:".into()
            } else {
                fixture.request_fields.signature.clone()
            },
        };
        let parsed = parse(
            if change == "status" { 201 } else { 200 },
            RESPONSE_BODY,
            &response_headers,
            "POST",
            if change == "uri" {
                "https://api.example/fapi/other"
            } else {
                "https://api.example/fapi/resource"
            },
            REQUEST_BODY,
            &request_headers,
            &altered_request_fields,
            fixture.response_fields,
        )
        .unwrap();
        assert_ne!(parsed.signature_base(), fixture.base, "change: {change}");
    }
}

#[test]
fn request_body_and_recomputed_request_digest_reconstruct_a_different_base() {
    let fixture = fixture();
    let changed_request_body = br#"{"amount":11}"#;
    let request_headers = request_headers(changed_request_body);
    let request_headers = borrowed(&request_headers);
    let response_headers = response_headers(RESPONSE_BODY);
    let response_headers = borrowed(&response_headers);

    let parsed = parse(
        200,
        RESPONSE_BODY,
        &response_headers,
        "POST",
        "https://api.example/fapi/resource",
        changed_request_body,
        &request_headers,
        &fixture.request_fields,
        fixture.response_fields,
    )
    .unwrap();
    assert_ne!(parsed.signature_base(), fixture.base);
}

#[test]
fn body_with_recomputed_digest_reconstructs_a_different_base() {
    let fixture = fixture();
    let changed_body = br#"{"approved":false}"#;
    let response_headers = response_headers(changed_body);
    let response_headers = borrowed(&response_headers);
    let request_headers = request_headers(REQUEST_BODY);
    let request_headers = borrowed(&request_headers);

    let parsed = parse(
        200,
        changed_body,
        &response_headers,
        "POST",
        "https://api.example/fapi/resource",
        REQUEST_BODY,
        &request_headers,
        &fixture.request_fields,
        fixture.response_fields,
    )
    .unwrap();
    assert_ne!(parsed.signature_base(), fixture.base);
}

#[test]
fn changed_body_with_stale_digest_is_rejected() {
    let fixture = fixture();
    let response_headers = response_headers(RESPONSE_BODY);
    let response_headers = borrowed(&response_headers);
    let request_headers = request_headers(REQUEST_BODY);
    let request_headers = borrowed(&request_headers);
    assert_eq!(
        parse(
            200,
            br#"{"approved":false}"#,
            &response_headers,
            "POST",
            "https://api.example/fapi/resource",
            REQUEST_BODY,
            &request_headers,
            &fixture.request_fields,
            fixture.response_fields,
        )
        .unwrap_err(),
        VerifyError::DigestMismatch
    );
}

#[test]
fn client_preserves_the_received_digest_field_value_in_the_signature_base() {
    let fixture = fixture();
    let response_digest = content_digest(RESPONSE_BODY);
    let varied_digest = format!("sha-512=:AA==: ,  {response_digest}");
    let response_headers = [("Content-Digest", varied_digest.as_str())];
    let request_headers = request_headers(REQUEST_BODY);
    let request_headers = borrowed(&request_headers);

    let parsed = parse(
        200,
        RESPONSE_BODY,
        &response_headers,
        "POST",
        "https://api.example/fapi/resource",
        REQUEST_BODY,
        &request_headers,
        &fixture.request_fields,
        fixture.response_fields,
    )
    .unwrap();
    let base = std::str::from_utf8(parsed.signature_base()).unwrap();
    assert!(base.contains(&format!("\"content-digest\": {varied_digest}")));
}

#[test]
fn client_rejects_a_digest_dictionary_with_a_non_digest_member() {
    let fixture = fixture();
    let malformed = format!("{}, bogus=\"not-a-digest\"", content_digest(RESPONSE_BODY));
    let response_headers = [("Content-Digest", malformed.as_str())];
    let request_headers = request_headers(REQUEST_BODY);
    let request_headers = borrowed(&request_headers);

    assert_eq!(
        parse(
            200,
            RESPONSE_BODY,
            &response_headers,
            "POST",
            "https://api.example/fapi/resource",
            REQUEST_BODY,
            &request_headers,
            &fixture.request_fields,
            fixture.response_fields,
        )
        .unwrap_err(),
        VerifyError::DigestMismatch
    );
}

#[test]
fn request_components_are_never_sourced_from_response_headers() {
    let fixture = fixture();
    let request_headers = request_headers(REQUEST_BODY);
    let request_headers = borrowed(&request_headers);
    let digest = content_digest(RESPONSE_BODY);
    let spoofed_response_headers = [
        ("Content-Digest", digest.as_str()),
        ("Signature-Input", "attacker-input"),
        ("Signature", "attacker-signature"),
    ];
    let parsed = parse(
        200,
        RESPONSE_BODY,
        &spoofed_response_headers,
        "POST",
        "https://api.example/fapi/resource",
        REQUEST_BODY,
        &request_headers,
        &fixture.request_fields,
        fixture.response_fields,
    )
    .unwrap();

    let base = std::str::from_utf8(parsed.signature_base()).unwrap();
    assert!(base.contains(&fixture.request_fields.signature_input));
    assert!(base.contains(&fixture.request_fields.signature));
    assert!(!base.contains("attacker-input"));
    assert!(!base.contains("attacker-signature"));
}

#[test]
fn client_requires_status_created_tag_and_exact_req_component_parameters() {
    type FieldMutation = (&'static str, fn(&mut SignatureFields));
    let mutations: &[FieldMutation] = &[
        ("status", |fields| {
            fields.signature_input = fields.signature_input.replace("\"@status\" ", "")
        }),
        ("created", |fields| {
            fields.signature_input = fields.signature_input.replace(";created=1720000000", "")
        }),
        ("tag", |fields| {
            fields.signature_input = fields
                .signature_input
                .replace("tag=\"fapi-2-response\"", "tag=\"other\"")
        }),
        ("request marker", |fields| {
            fields.signature_input = fields
                .signature_input
                .replace("\"@method\";req", "\"@method\"")
        }),
    ];
    for (name, mutate) in mutations {
        let mut fixture = fixture();
        mutate(&mut fixture.response_fields);
        let request_headers = request_headers(REQUEST_BODY);
        let request_headers = borrowed(&request_headers);
        let response_headers = response_headers(RESPONSE_BODY);
        let response_headers = borrowed(&response_headers);
        let result = parse(
            200,
            RESPONSE_BODY,
            &response_headers,
            "POST",
            "https://api.example/fapi/resource",
            REQUEST_BODY,
            &request_headers,
            &fixture.request_fields,
            fixture.response_fields,
        );
        assert!(result.is_err(), "mutation unexpectedly accepted: {name}");
    }
}
