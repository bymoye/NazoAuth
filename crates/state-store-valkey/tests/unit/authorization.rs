use super::{AuthorizationCodeBegin, parse_authorization_code_begin_reply};

#[test]
fn authorization_code_begin_reply_maps_terminal_states_exactly() {
    assert!(matches!(
        parse_authorization_code_begin_reply("busy"),
        Ok(AuthorizationCodeBegin::Busy)
    ));
    assert!(matches!(
        parse_authorization_code_begin_reply("failed"),
        Ok(AuthorizationCodeBegin::Failed)
    ));
    assert!(matches!(
        parse_authorization_code_begin_reply("missing"),
        Ok(AuthorizationCodeBegin::Missing)
    ));
    assert!(matches!(
        parse_authorization_code_begin_reply("malformed"),
        Ok(AuthorizationCodeBegin::Malformed)
    ));
    assert!(parse_authorization_code_begin_reply("unknown").is_err());
}

#[test]
fn authorization_code_begin_reply_rejects_malformed_structured_states() {
    assert!(parse_authorization_code_begin_reply("consuming|not-json").is_err());
    assert!(parse_authorization_code_begin_reply("consuming|[]").is_err());
    assert!(parse_authorization_code_begin_reply("consumed|not-json").is_err());
    assert!(parse_authorization_code_begin_reply("consumed|{\"status\":\"pending\"}").is_err());
}
