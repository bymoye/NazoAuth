use super::*;

#[test]
fn authorization_code_consumption_parser_accepts_only_pending_payload_for_consuming_state() {
    let payload = code_payload(true);
    let raw = format!("consuming|{}", serde_json::to_string(&payload).unwrap());

    match parse_authorization_code_consumption_response(&raw) {
        AuthorizationCodeConsumption::Consuming(parsed) => {
            assert_eq!(parsed.code_id, "code-1");
            assert_eq!(parsed.client_id, "client-1");
            assert_eq!(parsed.redirect_uri, "https://client.example/callback");
            assert_eq!(parsed.code_challenge_method.as_deref(), Some("S256"));
        }
        _ => panic!("pending authorization code payload should enter consuming state"),
    }

    assert!(matches!(
        parse_authorization_code_consumption_response("consuming|not-json"),
        AuthorizationCodeConsumption::Malformed
    ));
    assert!(matches!(
        parse_authorization_code_consumption_response("consuming|[]"),
        AuthorizationCodeConsumption::Malformed
    ));
}

#[test]
fn authorization_code_consumption_parser_accepts_only_consumed_marker_for_replay_state() {
    let marker = ConsumedAuthorizationCode {
        client_id: Uuid::now_v7(),
        access_token_jti: "access-jti-1".to_owned(),
        access_token_expires_at: Utc::now().timestamp() + 300,
        refresh_token_family_id: Some(Uuid::now_v7()),
        consumed_at: Utc::now(),
    };
    let consumed = serde_json::to_string(&AuthorizationCodeState::Consumed {
        marker: marker.clone(),
    })
    .unwrap();
    let raw = format!("consumed|{consumed}");

    match parse_authorization_code_consumption_response(&raw) {
        AuthorizationCodeConsumption::Consumed(parsed) => {
            assert_eq!(parsed.client_id, marker.client_id);
            assert_eq!(parsed.access_token_jti, "access-jti-1");
            assert_eq!(
                parsed.refresh_token_family_id,
                marker.refresh_token_family_id
            );
        }
        _ => panic!("consumed authorization code marker should be replay evidence"),
    }

    let failed = serde_json::to_string(&AuthorizationCodeState::Failed {
        failed_at: Utc::now(),
        error: "pkce_failed".to_owned(),
    })
    .unwrap();
    assert!(matches!(
        parse_authorization_code_consumption_response(&format!("consumed|{failed}")),
        AuthorizationCodeConsumption::Malformed
    ));
    assert!(matches!(
        parse_authorization_code_consumption_response("consumed|not-json"),
        AuthorizationCodeConsumption::Malformed
    ));
}

#[test]
fn authorization_code_consumption_parser_maps_terminal_states_fail_closed() {
    for (raw, expected) in [
        ("busy", "busy"),
        ("failed", "failed"),
        ("missing", "missing"),
        ("pending", "malformed"),
        ("ok", "malformed"),
        ("", "malformed"),
    ] {
        let parsed = parse_authorization_code_consumption_response(raw);
        let actual = match parsed {
            AuthorizationCodeConsumption::Busy => "busy",
            AuthorizationCodeConsumption::Failed => "failed",
            AuthorizationCodeConsumption::Missing => "missing",
            AuthorizationCodeConsumption::Malformed => "malformed",
            AuthorizationCodeConsumption::Consuming(_) => "consuming",
            AuthorizationCodeConsumption::Consumed(_) => "consumed",
        };
        assert_eq!(actual, expected, "unexpected parser result for {raw:?}");
    }
}
