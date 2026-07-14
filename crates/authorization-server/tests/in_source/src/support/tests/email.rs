use super::*;

#[test]
fn recipient_email_rejects_display_name_mailbox() {
    let err = match parse_email_recipient("Nazo <user@example.com>") {
        Ok(_) => panic!("display-name mailbox must be rejected"),
        Err(err) => err,
    };

    assert!(err.to_string().contains("email address is invalid"));
}

#[test]
fn recipient_email_is_normalized_and_has_no_display_name() {
    let recipient = parse_email_recipient(" USER@Example.COM ").unwrap();

    assert_eq!(recipient.normalized, "user@example.com");
    assert_eq!(recipient.mailbox.name, None);
    assert_eq!(recipient.mailbox.email.to_string(), "user@example.com");
}

#[test]
fn invalid_recipient_email_does_not_fallback_to_raw_input() {
    for raw in ["", "not an email", "user@example.com,other@example.com"] {
        let err = match parse_email_recipient(raw) {
            Ok(_) => panic!("invalid recipient must be rejected: {raw}"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("email address is invalid"));
    }
}

#[test]
fn html_part_uses_html_content_type() {
    let part = html_part("<p>hello</p>".to_owned());

    assert_eq!(
        part.headers().get::<ContentType>().unwrap(),
        ContentType::TEXT_HTML
    );
}

#[test]
fn delivery_adapter_projects_only_focused_smtp_configuration() {
    let smtp = SmtpEmailSettings {
        host: "smtp.example.test".to_owned(),
        port: 2525,
        tls: SmtpTlsMode::None,
        username: Some("mailer".to_owned()),
        password: Some("secret".to_owned()),
        from: "Nazo <no-reply@example.test>".parse().unwrap(),
    };
    let configured = SmtpVerificationEmailDelivery::from_delivery(&EmailDelivery::Smtp(smtp));
    assert!(configured.smtp.is_some());

    let disabled = SmtpVerificationEmailDelivery::from_delivery(&EmailDelivery::Disabled);
    assert!(disabled.smtp.is_none());

    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/adapters/email.rs"
    ));
    assert!(
        !source.contains("\n    settings: Arc<Settings>"),
        "the delivery adapter must not retain the aggregate Settings object"
    );
}
