use super::*;

#[test]
fn authorization_duplicate_parameters_includes_all_authorized_params_and_reauth() {
    let params = authorization_duplicate_parameters();
    assert!(params.contains(&"response_type"));
    assert!(params.contains(&"client_id"));
    assert!(params.contains(&"redirect_uri"));
    assert!(params.contains(&"scope"));
    assert!(!params.contains(&"resource"));
    assert!(params.contains(&"code_challenge"));
    assert!(params.contains(&"nonce"));
    assert!(params.contains(&"claims"));
    assert!(params.contains(&"prompt"));
    assert!(params.contains(&"response_mode"));
    assert!(params.contains(&"request_uri"));
    assert!(params.contains(&"request"));
    assert!(params.contains(&reauth_nonce_parameter()));
    assert!(AUTHORIZED_REQUEST_PARAMETERS.contains(&"resource"));
    assert_eq!(params.len(), AUTHORIZED_REQUEST_PARAMETERS.len());
}

#[test]
fn reauth_nonce_parameter_returns_expected_name() {
    assert_eq!(reauth_nonce_parameter(), "_nazo_reauth_nonce");
}

#[test]
fn authorization_request_requires_pkce_for_public_client() {
    let client = ClientRow {
        client_type: "public".to_owned(),
        require_dpop_bound_tokens: false,
        require_mtls_bound_tokens: false,
        allow_authorization_code_without_pkce: true,
        ..default_client_row()
    };
    assert!(authorization_request_requires_pkce(&client));
}

#[test]
fn authorization_request_requires_pkce_for_dpop_bound_client() {
    let client = ClientRow {
        client_type: "confidential".to_owned(),
        require_dpop_bound_tokens: true,
        require_mtls_bound_tokens: false,
        allow_authorization_code_without_pkce: true,
        ..default_client_row()
    };
    assert!(authorization_request_requires_pkce(&client));
}

#[test]
fn authorization_request_requires_pkce_for_mtls_bound_client() {
    let client = ClientRow {
        client_type: "confidential".to_owned(),
        require_dpop_bound_tokens: false,
        require_mtls_bound_tokens: true,
        allow_authorization_code_without_pkce: true,
        ..default_client_row()
    };
    assert!(authorization_request_requires_pkce(&client));
}

#[test]
fn authorization_request_requires_pkce_when_pkce_not_optional() {
    let client = ClientRow {
        client_type: "confidential".to_owned(),
        require_dpop_bound_tokens: false,
        require_mtls_bound_tokens: false,
        allow_authorization_code_without_pkce: false,
        ..default_client_row()
    };
    assert!(authorization_request_requires_pkce(&client));
}

#[test]
fn authorization_request_does_not_require_pkce_for_confidential_with_pkce_optional() {
    let client = ClientRow {
        client_type: "confidential".to_owned(),
        require_dpop_bound_tokens: false,
        require_mtls_bound_tokens: false,
        allow_authorization_code_without_pkce: true,
        ..default_client_row()
    };
    assert!(!authorization_request_requires_pkce(&client));
}

#[test]
fn authorization_pkce_accepts_missing_parameters() {
    let q = HashMap::new();
    assert_eq!(authorization_pkce(&q), Ok((None, None)));
}

#[test]
fn authorization_pkce_accepts_valid_s256_challenge() {
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let mut q = HashMap::new();
    q.insert("code_challenge".to_owned(), challenge.to_owned());
    q.insert("code_challenge_method".to_owned(), "S256".to_owned());
    let result = authorization_pkce(&q);
    assert_eq!(
        result,
        Ok((Some(challenge.to_owned()), Some("S256".to_owned())))
    );
}

#[test]
fn authorization_pkce_rejects_challenge_with_plain_method() {
    let mut q = HashMap::new();
    q.insert("code_challenge".to_owned(), "challenge".to_owned());
    q.insert("code_challenge_method".to_owned(), "plain".to_owned());
    assert_eq!(authorization_pkce(&q), Err(()));
}

#[test]
fn authorization_pkce_rejects_challenge_without_method() {
    let mut q = HashMap::new();
    q.insert(
        "code_challenge".to_owned(),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned(),
    );
    assert_eq!(authorization_pkce(&q), Err(()));
}

#[test]
fn authorization_pkce_rejects_short_challenge_with_s256() {
    let mut q = HashMap::new();
    q.insert("code_challenge".to_owned(), "short".to_owned());
    q.insert("code_challenge_method".to_owned(), "S256".to_owned());
    assert_eq!(authorization_pkce(&q), Err(()));
}

#[test]
fn authorization_pkce_rejects_long_challenge_with_s256() {
    let mut q = HashMap::new();
    q.insert("code_challenge".to_owned(), "a".repeat(129));
    q.insert("code_challenge_method".to_owned(), "S256".to_owned());
    assert_eq!(authorization_pkce(&q), Err(()));
}

#[test]
fn authorization_response_mode_defaults_to_none_when_absent() {
    let q = HashMap::new();
    assert_eq!(authorization_response_mode(&q), Ok(None));
}

#[test]
fn authorization_response_mode_accepts_query_as_none() {
    let mut q = HashMap::new();
    q.insert("response_mode".to_owned(), "query".to_owned());
    assert_eq!(authorization_response_mode(&q), Ok(None));
}

#[test]
fn authorization_response_mode_accepts_jwt() {
    let mut q = HashMap::new();
    q.insert("response_mode".to_owned(), "jwt".to_owned());
    assert_eq!(authorization_response_mode(&q), Ok(Some("jwt".to_owned())));
}

#[test]
fn authorization_response_mode_rejects_form_post() {
    let mut q = HashMap::new();
    q.insert("response_mode".to_owned(), "form_post".to_owned());
    assert_eq!(authorization_response_mode(&q), Err(()));
}

#[test]
fn authorization_response_mode_rejects_unknown_value() {
    let mut q = HashMap::new();
    q.insert("response_mode".to_owned(), "fragment".to_owned());
    assert_eq!(authorization_response_mode(&q), Err(()));
}

#[test]
fn requested_acr_selects_supported_query_acr_value() {
    let mut q = HashMap::new();
    q.insert("acr_values".to_owned(), "2 1".to_owned());
    assert_eq!(requested_acr(&q, None), Ok(Some("1".to_owned())));
}

#[test]
fn requested_acr_returns_none_when_acr_values_are_all_empty() {
    let mut q = HashMap::new();
    q.insert("acr_values".to_owned(), "   ".to_owned());
    assert_eq!(requested_acr(&q, None), Ok(None));
}

#[test]
fn requested_acr_ignores_unsupported_voluntary_claims_acr() {
    let q = HashMap::new();
    let claim = OidcClaimRequest {
        name: "acr".to_owned(),
        essential: false,
        value: Some(json!("phr")),
        values: Vec::new(),
    };
    assert_eq!(requested_acr(&q, Some(&claim)), Ok(None));
}

#[test]
fn requested_acr_does_not_trust_query_or_claims() {
    let mut q = HashMap::new();
    q.insert("acr_values".to_owned(), "phr".to_owned());
    let claim = OidcClaimRequest {
        name: "acr".to_owned(),
        essential: false,
        value: Some(json!("urn:mace:incommon:iap:bronze")),
        values: Vec::new(),
    };
    assert_eq!(requested_acr(&q, Some(&claim)), Ok(None));
}

#[test]
fn requested_acr_returns_none_when_both_absent() {
    let q = HashMap::new();
    assert_eq!(requested_acr(&q, None), Ok(None));
}

#[test]
fn requested_prompt_returns_default_when_absent() {
    let q = HashMap::new();
    assert_eq!(requested_prompt(&q), Ok(PromptDirectives::default()));
    assert!(!requested_prompt(&q).unwrap().login);
    assert!(!requested_prompt(&q).unwrap().consent);
    assert!(!requested_prompt(&q).unwrap().select_account);
    assert!(!requested_prompt(&q).unwrap().none);
}

#[test]
fn requested_prompt_accepts_login() {
    let mut q = HashMap::new();
    q.insert("prompt".to_owned(), "login".to_owned());
    let result = requested_prompt(&q).unwrap();
    assert!(result.login);
    assert!(!result.consent);
    assert!(!result.select_account);
    assert!(!result.none);
}

#[test]
fn requested_prompt_accepts_consent() {
    let mut q = HashMap::new();
    q.insert("prompt".to_owned(), "consent".to_owned());
    let result = requested_prompt(&q).unwrap();
    assert!(!result.login);
    assert!(result.consent);
    assert!(!result.select_account);
    assert!(!result.none);
}

#[test]
fn requested_prompt_accepts_select_account() {
    let mut q = HashMap::new();
    q.insert("prompt".to_owned(), "select_account".to_owned());
    let result = requested_prompt(&q).unwrap();
    assert!(!result.login);
    assert!(!result.consent);
    assert!(result.select_account);
    assert!(!result.none);
}

#[test]
fn requested_prompt_accepts_none() {
    let mut q = HashMap::new();
    q.insert("prompt".to_owned(), "none".to_owned());
    let result = requested_prompt(&q).unwrap();
    assert!(!result.login);
    assert!(!result.consent);
    assert!(!result.select_account);
    assert!(result.none);
}

#[test]
fn requested_prompt_accepts_multiple_directives() {
    let mut q = HashMap::new();
    q.insert("prompt".to_owned(), "login consent".to_owned());
    let result = requested_prompt(&q).unwrap();
    assert!(result.login);
    assert!(result.consent);
    assert!(!result.select_account);
    assert!(!result.none);
}

#[test]
fn requested_prompt_accepts_empty_string() {
    let mut q = HashMap::new();
    q.insert("prompt".to_owned(), "".to_owned());
    let result = requested_prompt(&q).unwrap();
    assert_eq!(result, PromptDirectives::default());
}

#[test]
fn requested_prompt_rejects_unknown_directive() {
    let mut q = HashMap::new();
    q.insert("prompt".to_owned(), "unknown".to_owned());
    assert_eq!(requested_prompt(&q), Err(()));
}

#[test]
fn requested_prompt_rejects_none_combined_with_login() {
    let mut q = HashMap::new();
    q.insert("prompt".to_owned(), "none login".to_owned());
    assert_eq!(requested_prompt(&q), Err(()));
}

#[test]
fn requested_prompt_rejects_none_combined_with_consent() {
    let mut q = HashMap::new();
    q.insert("prompt".to_owned(), "none consent".to_owned());
    assert_eq!(requested_prompt(&q), Err(()));
}

#[test]
fn requested_prompt_rejects_none_combined_with_select_account() {
    let mut q = HashMap::new();
    q.insert("prompt".to_owned(), "none select_account".to_owned());
    assert_eq!(requested_prompt(&q), Err(()));
}

#[test]
fn requested_claims_returns_empty_when_absent() {
    let q = HashMap::new();
    let result = requested_claims(&q).unwrap();
    assert!(result.userinfo.is_empty());
    assert!(result.id_token.is_empty());
    assert_eq!(result.acr, None);
    assert!(!result.auth_time);
}

#[test]
fn requested_claims_rejects_invalid_json() {
    let mut q = HashMap::new();
    q.insert("claims".to_owned(), "{invalid".to_owned());
    assert_eq!(requested_claims(&q), Err(()));
}

#[test]
fn requested_claims_accepts_non_object_json_without_results() {
    let mut q = HashMap::new();
    q.insert("claims".to_owned(), r#""string""#.to_owned());
    let result = requested_claims(&q).unwrap();
    assert!(result.userinfo.is_empty());
    assert!(result.id_token.is_empty());
    assert!(result.acr.is_none());
    assert!(!result.auth_time);
}

#[test]
fn requested_claims_parses_userinfo_claims() {
    let mut q = HashMap::new();
    q.insert(
        "claims".to_owned(),
        r#"{"userinfo":{"name":null,"email":null}}"#.to_owned(),
    );
    let result = requested_claims(&q).unwrap();
    assert_eq!(result.userinfo.len(), 2);
    assert_eq!(result.userinfo[0].name, "email");
    assert_eq!(result.userinfo[1].name, "name");
    assert!(result.id_token.is_empty());
}

#[test]
fn requested_claims_parses_id_token_claims() {
    let mut q = HashMap::new();
    q.insert(
        "claims".to_owned(),
        r#"{"id_token":{"sub":null,"name":null}}"#.to_owned(),
    );
    let result = requested_claims(&q).unwrap();
    assert!(result.userinfo.is_empty());
    assert_eq!(result.id_token.len(), 1);
    assert_eq!(result.id_token[0].name, "name");
}

#[test]
fn requested_claims_preserves_acr_claim_with_value() {
    let mut q = HashMap::new();
    q.insert(
        "claims".to_owned(),
        r#"{"id_token":{"acr":{"value":"phr"}}}"#.to_owned(),
    );
    let result = requested_claims(&q).unwrap();
    assert_eq!(
        result.acr.and_then(|request| request.value),
        Some(json!("phr"))
    );
}

#[test]
fn requested_acr_satisfies_supported_essential_claim_request() {
    let mut q = HashMap::new();
    q.insert(
        "claims".to_owned(),
        r#"{"id_token":{"acr":{"essential":true,"value":"1"}}}"#.to_owned(),
    );
    let claims = requested_claims(&q).expect("claims request should parse");

    assert_eq!(
        requested_acr(&q, claims.acr.as_ref()),
        Ok(Some("1".to_owned()))
    );
}

#[test]
fn requested_acr_rejects_unsupported_essential_claim_request() {
    let mut q = HashMap::new();
    q.insert(
        "claims".to_owned(),
        r#"{"id_token":{"acr":{"essential":true,"value":"phr"}}}"#.to_owned(),
    );
    let claims = requested_claims(&q).expect("claims request should parse");

    assert_eq!(requested_acr(&q, claims.acr.as_ref()), Err(()));
}

#[test]
fn requested_claims_preserves_acr_claim_with_values() {
    let mut q = HashMap::new();
    q.insert(
        "claims".to_owned(),
        r#"{"id_token":{"acr":{"values":["phr","phrh"]}}}"#.to_owned(),
    );
    let result = requested_claims(&q).unwrap();
    assert_eq!(
        result.acr.expect("ACR request should be preserved").values,
        vec![json!("phr"), json!("phrh")]
    );
}

#[test]
fn requested_claims_preserves_blank_acr_value_for_satisfaction_decision() {
    let mut q = HashMap::new();
    q.insert(
        "claims".to_owned(),
        r#"{"id_token":{"acr":{"value":"   "}}}"#.to_owned(),
    );
    let result = requested_claims(&q).unwrap();
    assert_eq!(
        result.acr.and_then(|request| request.value),
        Some(json!("   "))
    );
}

#[test]
fn requested_claims_preserves_mixed_acr_values() {
    let mut q = HashMap::new();
    q.insert(
        "claims".to_owned(),
        r#"{"id_token":{"acr":{"values":["  ","phr","phrh"]}}}"#.to_owned(),
    );
    let result = requested_claims(&q).unwrap();
    assert_eq!(
        result.acr.expect("ACR request should be preserved").values,
        vec![json!("  "), json!("phr"), json!("phrh")]
    );
}

#[test]
fn validate_acr_claim_rejects_non_object_id_token_claims() {
    assert_eq!(validate_acr_claim(Some(&json!("invalid"))), Err(()));
}

#[test]
fn validate_acr_claim_accepts_valid_acr_claim_requests() {
    assert_eq!(validate_acr_claim(Some(&json!({}))), Ok(()));
    assert_eq!(validate_acr_claim(Some(&json!({"acr":"phr"}))), Err(()));
    assert_eq!(validate_acr_claim(Some(&json!({"acr":null}))), Ok(()));
    assert_eq!(
        validate_acr_claim(Some(&json!({"acr":{"values":[" ",""]}}))),
        Ok(())
    );
}

#[test]
fn requested_auth_time_claim_rejects_non_object_id_token_claims() {
    assert_eq!(requested_auth_time_claim(Some(&json!("invalid"))), Err(()));
}

#[test]
fn requested_claims_parses_auth_time_claim() {
    let mut q = HashMap::new();
    q.insert(
        "claims".to_owned(),
        r#"{"id_token":{"auth_time":{"essential":true}}}"#.to_owned(),
    );
    let result = requested_claims(&q).unwrap();
    assert!(result.auth_time);
}

#[test]
fn requested_claims_parses_essential_claim() {
    let mut q = HashMap::new();
    q.insert(
        "claims".to_owned(),
        r#"{"userinfo":{"name":{"essential":true}}}"#.to_owned(),
    );
    let result = requested_claims(&q).unwrap();
    assert_eq!(result.userinfo.len(), 1);
    assert!(result.userinfo[0].essential);
}

#[test]
fn requested_claims_parses_claim_with_value() {
    let mut q = HashMap::new();
    q.insert(
        "claims".to_owned(),
        r#"{"userinfo":{"name":{"value":"John"}}}"#.to_owned(),
    );
    let result = requested_claims(&q).unwrap();
    assert_eq!(result.userinfo.len(), 1);
    assert_eq!(result.userinfo[0].value, Some(json!("John")));
}

#[test]
fn requested_claims_parses_claim_with_values() {
    let mut q = HashMap::new();
    q.insert(
        "claims".to_owned(),
        r#"{"userinfo":{"name":{"values":["John","Jane"]}}}"#.to_owned(),
    );
    let result = requested_claims(&q).unwrap();
    assert_eq!(result.userinfo.len(), 1);
    assert_eq!(
        result.userinfo[0].values,
        vec![json!("John"), json!("Jane")]
    );
}

#[test]
fn requested_claims_rejects_userinfo_non_object() {
    let mut q = HashMap::new();
    q.insert("claims".to_owned(), r#"{"userinfo":"string"}"#.to_owned());
    assert_eq!(requested_claims(&q), Err(()));
}

#[test]
fn requested_claims_rejects_id_token_non_object() {
    let mut q = HashMap::new();
    q.insert("claims".to_owned(), r#"{"id_token":["array"]}"#.to_owned());
    assert_eq!(requested_claims(&q), Err(()));
}

#[test]
fn requested_claims_rejects_claim_with_both_value_and_values() {
    let mut q = HashMap::new();
    q.insert(
        "claims".to_owned(),
        r#"{"userinfo":{"name":{"value":"x","values":["y"]}}}"#.to_owned(),
    );
    assert_eq!(requested_claims(&q), Err(()));
}

#[test]
fn requested_claims_rejects_claim_with_empty_values() {
    let mut q = HashMap::new();
    q.insert(
        "claims".to_owned(),
        r#"{"userinfo":{"name":{"values":[]}}}"#.to_owned(),
    );
    assert_eq!(requested_claims(&q), Err(()));
}

#[test]
fn requested_claims_rejects_claim_with_non_boolean_essential() {
    let mut q = HashMap::new();
    q.insert(
        "claims".to_owned(),
        r#"{"userinfo":{"name":{"essential":"yes"}}}"#.to_owned(),
    );
    assert_eq!(requested_claims(&q), Err(()));
}

#[test]
fn claim_request_names_returns_sorted_deduped_names() {
    let requests = vec![
        OidcClaimRequest {
            name: "name".to_owned(),
            essential: false,
            value: None,
            values: Vec::new(),
        },
        OidcClaimRequest {
            name: "email".to_owned(),
            essential: true,
            value: None,
            values: Vec::new(),
        },
        OidcClaimRequest {
            name: "email".to_owned(),
            essential: false,
            value: None,
            values: Vec::new(),
        },
    ];
    let names = claim_request_names(&requests);
    assert_eq!(names.len(), 3);
    assert!(names.contains(&"name".to_owned()));
    assert!(names.contains(&"email".to_owned()));
}

#[test]
fn claim_request_names_returns_empty_for_empty_slice() {
    assert!(claim_request_names(&[]).is_empty());
}

#[test]
fn preserve_verified_dpop_binding_inserts_when_missing() {
    let mut q = HashMap::new();
    preserve_verified_dpop_binding(&mut q, Some("test-jkt"));
    assert_eq!(q.get("dpop_jkt").map(String::as_str), Some("test-jkt"));
}

#[test]
fn preserve_verified_dpop_binding_does_not_overwrite_existing() {
    let mut q = HashMap::new();
    q.insert("dpop_jkt".to_owned(), "existing-jkt".to_owned());
    preserve_verified_dpop_binding(&mut q, Some("new-jkt"));
    assert_eq!(q.get("dpop_jkt").map(String::as_str), Some("existing-jkt"));
}

#[test]
fn preserve_verified_dpop_binding_noops_when_dpop_jkt_is_none() {
    let mut q = HashMap::new();
    preserve_verified_dpop_binding(&mut q, None);
    assert!(q.is_empty());
}

#[test]
fn session_requires_reauthentication_false_when_no_conditions() {
    let prompt = PromptDirectives::default();
    assert!(!session_requires_reauthentication(
        prompt, None, 1000, None, 2000
    ));
}

#[test]
fn session_requires_reauthentication_true_when_login_prompt_and_auth_time_before_reauth() {
    let prompt = PromptDirectives {
        login: true,
        ..Default::default()
    };
    assert!(session_requires_reauthentication(
        prompt,
        None,
        1000,
        Some(1500),
        2000
    ));
}

#[test]
fn session_requires_reauthentication_false_when_login_prompt_and_auth_time_after_reauth() {
    let prompt = PromptDirectives {
        login: true,
        ..Default::default()
    };
    assert!(!session_requires_reauthentication(
        prompt,
        None,
        2000,
        Some(1500),
        2500
    ));
}

#[test]
fn session_requires_reauthentication_true_when_select_account_and_auth_time_before_reauth() {
    let prompt = PromptDirectives {
        select_account: true,
        ..Default::default()
    };
    assert!(session_requires_reauthentication(
        prompt,
        None,
        1000,
        Some(1500),
        2000
    ));
}

#[test]
fn session_requires_reauthentication_true_when_max_age_is_zero() {
    let prompt = PromptDirectives::default();
    assert!(session_requires_reauthentication(
        prompt,
        Some(0),
        1000,
        None,
        2000
    ));
}

#[test]
fn session_requires_reauthentication_true_when_max_age_exceeded() {
    let prompt = PromptDirectives::default();
    assert!(session_requires_reauthentication(
        prompt,
        Some(5),
        0,
        None,
        100
    ));
}

#[test]
fn session_requires_reauthentication_false_when_max_age_not_exceeded() {
    let prompt = PromptDirectives::default();
    assert!(!session_requires_reauthentication(
        prompt,
        Some(100),
        90,
        None,
        100
    ));
}

#[test]
fn session_requires_reauthentication_handles_login_without_reauth_started_at() {
    let prompt = PromptDirectives {
        login: true,
        ..Default::default()
    };
    assert!(session_requires_reauthentication(
        prompt, None, 1000, None, 2000
    ));
}

#[test]
fn session_requires_reauthentication_false_when_none_prompt_without_conditions() {
    let prompt = PromptDirectives {
        none: true,
        ..Default::default()
    };
    assert!(!session_requires_reauthentication(
        prompt, None, 1000, None, 2000
    ));
}

#[test]
fn outer_request_uri_parameters_match_pushed_accepts_when_all_match() {
    let mut outer = HashMap::new();
    outer.insert("scope".to_owned(), "openid".to_owned());
    outer.insert("client_id".to_owned(), "client".to_owned());
    let mut pushed = HashMap::new();
    pushed.insert("scope".to_owned(), "openid".to_owned());
    pushed.insert("client_id".to_owned(), "different-client".to_owned());
    assert!(outer_request_uri_parameters_match_pushed(&outer, &pushed));
}

#[test]
fn outer_request_uri_parameters_match_pushed_rejects_mismatch() {
    let mut outer = HashMap::new();
    outer.insert("scope".to_owned(), "openid".to_owned());
    outer.insert("redirect_uri".to_owned(), "https://example.com".to_owned());
    let mut pushed = HashMap::new();
    pushed.insert("scope".to_owned(), "profile".to_owned());
    pushed.insert("redirect_uri".to_owned(), "https://example.com".to_owned());
    assert!(!outer_request_uri_parameters_match_pushed(&outer, &pushed));
}

#[test]
fn outer_request_uri_parameters_match_pushed_ignores_request_uri() {
    let mut outer = HashMap::new();
    outer.insert(
        "request_uri".to_owned(),
        "urn:ietf:params:oauth:request_uri:abc".to_owned(),
    );
    let pushed = HashMap::new();
    assert!(outer_request_uri_parameters_match_pushed(&outer, &pushed));
}

#[test]
fn outer_request_uri_parameters_match_pushed_ignores_client_id() {
    let mut outer = HashMap::new();
    outer.insert("client_id".to_owned(), "client-a".to_owned());
    let mut pushed = HashMap::new();
    pushed.insert("client_id".to_owned(), "client-b".to_owned());
    assert!(outer_request_uri_parameters_match_pushed(&outer, &pushed));
}

#[test]
fn outer_request_uri_parameters_match_pushed_handles_empty_outer() {
    let outer = HashMap::new();
    let mut pushed = HashMap::new();
    pushed.insert("scope".to_owned(), "openid".to_owned());
    assert!(outer_request_uri_parameters_match_pushed(&outer, &pushed));
}

#[test]
fn fapi_outer_request_uri_parameters_allow_only_client_id_and_request_uri() {
    let mut outer = HashMap::new();
    outer.insert("client_id".to_owned(), "client-a".to_owned());
    outer.insert(
        "request_uri".to_owned(),
        "urn:ietf:params:oauth:request_uri:abc".to_owned(),
    );
    assert!(outer_request_uri_parameters_are_fapi_compliant(&outer));

    outer.insert(
        "redirect_uri".to_owned(),
        "https://client.example/callback".to_owned(),
    );
    assert!(!outer_request_uri_parameters_are_fapi_compliant(&outer));
}

#[test]
fn append_authorization_response_query_appends_code_and_iss() {
    let url = append_authorization_response_query(
        "https://client.example/cb",
        "https://issuer.example",
        Some("auth-code"),
        None,
        None,
        None,
    );
    assert!(url.contains("code=auth-code"));
    assert!(url.contains("iss=https%3A%2F%2Fissuer.example"));
}

#[test]
fn append_authorization_response_query_appends_error_and_iss() {
    let url = append_authorization_response_query(
        "https://client.example/cb",
        "https://issuer.example",
        None,
        Some("invalid_request"),
        None,
        None,
    );
    assert!(url.contains("error=invalid_request"));
    assert!(url.contains("iss=https%3A%2F%2Fissuer.example"));
}

#[test]
fn append_authorization_response_query_appends_state_and_iss() {
    let url = append_authorization_response_query(
        "https://client.example/cb",
        "https://issuer.example",
        None,
        None,
        Some("state123"),
        None,
    );
    assert!(url.contains("state=state123"));
    assert!(url.contains("iss=https%3A%2F%2Fissuer.example"));
}

#[test]
fn append_authorization_response_query_appends_session_state_when_present() {
    let url = append_authorization_response_query(
        "https://client.example/cb",
        "https://issuer.example",
        Some("code"),
        None,
        Some("state"),
        Some("session.hash.salt"),
    );
    assert!(url.contains("code=code"));
    assert!(url.contains("state=state"));
    assert!(url.contains("session_state=session.hash.salt"));
    assert!(url.contains("iss=https%3A%2F%2Fissuer.example"));
}

#[test]
fn append_authorization_response_query_appends_all_parameters() {
    let url = append_authorization_response_query(
        "https://client.example/cb",
        "https://issuer.example",
        Some("code"),
        Some("error"),
        Some("state"),
        None,
    );
    assert!(url.contains("code=code"));
    assert!(url.contains("error=error"));
    assert!(url.contains("state=state"));
    assert!(url.contains("iss=https%3A%2F%2Fissuer.example"));
}

#[test]
fn append_authorization_response_query_returns_original_on_parse_failure() {
    let url = append_authorization_response_query(
        "not a url",
        "https://issuer.example",
        Some("code"),
        None,
        None,
        None,
    );
    assert_eq!(url, "not a url");
}

#[test]
fn append_authorization_response_query_preserves_existing_query() {
    let url = append_authorization_response_query(
        "https://client.example/cb?existing=param",
        "https://issuer.example",
        Some("code"),
        None,
        Some("state"),
        None,
    );
    assert!(url.contains("existing=param"));
    assert!(url.contains("code=code"));
    assert!(url.contains("state=state"));
}

#[test]
fn authorization_nonce_too_long_returns_true_when_nonce_exceeds_max() {
    let mut q = HashMap::new();
    q.insert("nonce".to_owned(), "x".repeat(257));
    assert!(authorization_nonce_too_long(&q));
}

#[test]
fn authorization_nonce_too_long_returns_false_when_nonce_at_max() {
    let mut q = HashMap::new();
    q.insert("nonce".to_owned(), "x".repeat(256));
    assert!(!authorization_nonce_too_long(&q));
}

#[test]
fn authorization_nonce_too_long_returns_false_when_nonce_under_max() {
    let mut q = HashMap::new();
    q.insert("nonce".to_owned(), "short".to_owned());
    assert!(!authorization_nonce_too_long(&q));
}

#[test]
fn authorization_nonce_too_long_returns_false_when_nonce_absent() {
    let q = HashMap::new();
    assert!(!authorization_nonce_too_long(&q));
}

#[test]
fn authorization_login_query_returns_original_when_request_uri_is_some() {
    let mut expanded = HashMap::new();
    expanded.insert("scope".to_owned(), "openid".to_owned());
    let mut original = HashMap::new();
    original.insert(
        "request_uri".to_owned(),
        "urn:ietf:params:oauth:request_uri:abc".to_owned(),
    );
    let result = authorization_login_query(
        &expanded,
        &original,
        Some(&"urn:ietf:params:oauth:request_uri:abc".to_owned()),
    );
    assert_eq!(
        result.get("request_uri").map(String::as_str),
        Some("urn:ietf:params:oauth:request_uri:abc")
    );
    assert!(!result.contains_key("scope"));
}

#[test]
fn authorization_login_query_returns_expanded_when_request_uri_is_none() {
    let mut expanded = HashMap::new();
    expanded.insert("scope".to_owned(), "openid".to_owned());
    let original = HashMap::new();
    let result = authorization_login_query(&expanded, &original, None);
    assert_eq!(result.get("scope").map(String::as_str), Some("openid"));
}

#[test]
fn authorization_login_url_for_frontend_without_reauthentication() {
    let mut q = HashMap::new();
    q.insert("response_type".to_owned(), "code".to_owned());
    q.insert("client_id".to_owned(), "my-client".to_owned());
    let url = authorization_login_url_for_frontend("https://app.example", &q, None);
    assert!(url.starts_with("https://app.example/auth?next="));
    assert!(url.contains(urlencoding::encode("/authorize?").as_ref()));
    assert!(url.contains("response_type%3Dcode") || url.contains("response_type=code"));
    assert!(url.contains("client_id%3Dmy-client") || url.contains("client_id=my-client"));
    assert!(!url.contains(reauth_nonce_parameter()));
}

#[test]
fn authorization_login_url_for_frontend_with_reauthentication() {
    let mut q = HashMap::new();
    q.insert("client_id".to_owned(), "my-client".to_owned());
    let url = authorization_login_url_for_frontend("https://app.example", &q, Some("server-nonce"));
    assert!(url.starts_with("https://app.example/auth?next="));
    assert!(url.contains(reauth_nonce_parameter()));
    assert!(url.contains("server-nonce"));
}

#[test]
fn authorization_login_url_for_frontend_with_empty_query() {
    let q = HashMap::new();
    let url = authorization_login_url_for_frontend("https://app.example", &q, None);
    assert_eq!(url, "https://app.example/auth?next=%2Fauthorize");
}

#[test]
fn authorization_login_url_for_frontend_trims_trailing_slash_from_base() {
    let mut q = HashMap::new();
    q.insert("client_id".to_owned(), "c".to_owned());
    let url = authorization_login_url_for_frontend("https://app.example/", &q, None);
    assert!(url.starts_with("https://app.example/auth?next="));
}

fn default_client_row() -> ClientRow {
    ClientRow {
        id: Uuid::from_u128(1),
        tenant_id: Uuid::from_u128(1),
        realm_id: Uuid::from_u128(2),
        organization_id: Uuid::from_u128(3),
        client_id: "test-client".to_owned(),
        client_name: "Test Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!(["https://client.example/cb"]),
        scopes: json!(["openid"]),
        allowed_audiences: json!(["https://api.example"]),
        grant_types: json!(["authorization_code"]),
        token_endpoint_auth_method: "client_secret_basic".to_owned(),
        require_dpop_bound_tokens: false,
        require_mtls_bound_tokens: false,
        tls_client_auth_subject_dn: None,
        tls_client_auth_cert_sha256: None,
        tls_client_auth_san_dns: json!([]),
        tls_client_auth_san_uri: json!([]),
        tls_client_auth_san_ip: json!([]),
        tls_client_auth_san_email: json!([]),
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: false,
        allow_authorization_code_without_pkce: true,
        is_active: true,
        jwks: None,
        introspection_encrypted_response_alg: None,
        introspection_encrypted_response_enc: None,
        userinfo_signed_response_alg: None,
        userinfo_encrypted_response_alg: None,
        userinfo_encrypted_response_enc: None,
        authorization_signed_response_alg: None,
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: false,
        subject_type: "public".to_owned(),
        sector_identifier_uri: None,
        sector_identifier_host: None,
    }
}
