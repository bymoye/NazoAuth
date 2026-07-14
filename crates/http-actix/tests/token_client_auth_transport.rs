use actix_web::{http::header, test::TestRequest};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use nazo_auth::{TokenEndpointError, token_client_authentication_context};
use nazo_http_actix::{
    TokenClientAuthForm, TokenClientAuthTransportFacts, token_client_auth_transport_facts,
};

fn facts(
    authorization: Option<&str>,
    form: TokenClientAuthForm<'_>,
) -> TokenClientAuthTransportFacts {
    let mut request = TestRequest::post().uri("/token");
    if let Some(authorization) = authorization {
        request = request.insert_header((header::AUTHORIZATION, authorization));
    }
    token_client_auth_transport_facts(&request.to_http_request(), form)
}

#[test]
fn basic_credentials_are_parsed_once_and_secrets_are_redacted() {
    let encoded = STANDARD.encode("client-1:very-secret");
    let facts = facts(
        Some(&format!("Basic {encoded}")),
        TokenClientAuthForm::default(),
    );
    assert!(facts.basic_challenge());
    let credentials = facts.presented_credentials(None, None);
    assert_eq!(credentials.client_id.as_deref(), Some("client-1"));
    assert_eq!(credentials.client_secret.as_deref(), Some("very-secret"));
    assert_eq!(credentials.method, "client_secret_basic");
    let debug = format!("{facts:?}");
    assert!(!debug.contains("very-secret"));
    assert!(debug.contains("[REDACTED]"));
}

#[test]
fn basic_credentials_decode_each_form_urlencoded_component() {
    let encoded = STANDARD.encode("client%3Aid%25%2B%E9%9B%AA:secret%3A%25%2B%E5%AF%86");
    let credentials = facts(
        Some(&format!("Basic {encoded}")),
        TokenClientAuthForm::default(),
    )
    .presented_credentials(None, None);
    assert_eq!(credentials.client_id.as_deref(), Some("client:id%+雪"));
    assert_eq!(credentials.client_secret.as_deref(), Some("secret:%+密"));

    let plus_as_space = STANDARD.encode("client+name:secret+phrase");
    let credentials = facts(
        Some(&format!("Basic {plus_as_space}")),
        TokenClientAuthForm::default(),
    )
    .presented_credentials(None, None);
    assert_eq!(credentials.client_id.as_deref(), Some("client name"));
    assert_eq!(credentials.client_secret.as_deref(), Some("secret phrase"));
}

#[test]
fn malformed_basic_remains_present_for_challenge_and_conflict_policy() {
    let malformed = facts(Some("Basic !!!"), TokenClientAuthForm::default());
    assert!(malformed.basic_challenge());
    let credentials = malformed.presented_credentials(None, None);
    assert!(credentials.client_id.is_none());
    assert_eq!(credentials.method, "client_secret_basic");

    let conflicting = facts(
        Some("Basic !!!"),
        TokenClientAuthForm {
            client_id: Some("client-1"),
            ..TokenClientAuthForm::default()
        },
    );
    assert_eq!(
        token_client_authentication_context(conflicting.presentation()),
        Err(TokenEndpointError::InvalidRequest)
    );
    let credentials = conflicting.presented_credentials(None, None);
    assert!(credentials.client_id.is_none());
    assert_eq!(credentials.method, "client_secret_basic");
}

#[test]
fn malformed_form_encoding_and_utf8_fail_closed_without_source_fallback() {
    for raw in ["client:%", "client:%2", "client:%GG", "client:%FF"] {
        let encoded = STANDARD.encode(raw);
        let facts = facts(
            Some(&format!("Basic {encoded}")),
            TokenClientAuthForm {
                client_id: Some("fallback"),
                client_secret: Some("fallback-secret"),
                ..TokenClientAuthForm::default()
            },
        );
        assert!(facts.basic_challenge());
        assert_eq!(
            token_client_authentication_context(facts.presentation()),
            Err(TokenEndpointError::InvalidRequest)
        );
        let credentials = facts.presented_credentials(None, None);
        assert!(credentials.client_id.is_none());
        assert!(credentials.client_secret.is_none());
        assert_eq!(credentials.method, "client_secret_basic");
    }
}

#[test]
fn assertion_basic_form_mtls_and_public_sources_have_fixed_precedence() {
    let assertion = facts(
        Some(&format!("Basic {}", STANDARD.encode("basic:secret"))),
        TokenClientAuthForm {
            client_id: Some("form"),
            client_secret: Some("form-secret"),
            client_assertion_type: Some("jwt-bearer"),
            client_assertion: Some("assertion"),
        },
    );
    let credentials = assertion.presented_credentials(Some("assertion-client".to_owned()), None);
    assert_eq!(credentials.method, "private_key_jwt");
    assert_eq!(credentials.client_id.as_deref(), Some("assertion-client"));
    assert_eq!(credentials.client_assertion.as_deref(), Some("assertion"));

    let post = facts(
        None,
        TokenClientAuthForm {
            client_id: Some("form"),
            client_secret: Some("form-secret"),
            ..TokenClientAuthForm::default()
        },
    )
    .presented_credentials(None, Some("form".to_owned()));
    assert_eq!(post.method, "client_secret_post");

    let mtls = facts(
        None,
        TokenClientAuthForm {
            client_id: Some("mtls"),
            ..TokenClientAuthForm::default()
        },
    )
    .presented_credentials(None, Some("mtls".to_owned()));
    assert_eq!(mtls.method, "tls_client_auth");

    let public = facts(
        None,
        TokenClientAuthForm {
            client_id: Some("public"),
            ..TokenClientAuthForm::default()
        },
    )
    .presented_credentials(None, None);
    assert_eq!(public.method, "none");
}

#[test]
fn assertion_fields_and_missing_form_client_mtls_are_preserved_as_facts() {
    let assertion = facts(
        None,
        TokenClientAuthForm {
            client_assertion_type: Some("urn:assertion"),
            client_assertion: Some("jwt"),
            ..TokenClientAuthForm::default()
        },
    );
    assert_eq!(assertion.client_assertion_type(), Some("urn:assertion"));
    assert_eq!(assertion.client_assertion(), Some("jwt"));

    let mtls = facts(None, TokenClientAuthForm::default())
        .presented_credentials(None, Some("certificate-client".to_owned()));
    assert_eq!(mtls.client_id.as_deref(), Some("certificate-client"));
    assert_eq!(mtls.method, "tls_client_auth");
}
