use super::*;

#[test]
fn every_public_help_topic_is_complete_without_runtime_state() {
    for (topic, expected) in [
        (cli::HelpTopic::TopLevel, "Commands:"),
        (cli::HelpTopic::Install, "--external-dependencies"),
        (cli::HelpTopic::Update, "--accept-migration-barrier"),
        (cli::HelpTopic::Keys, "register-external"),
        (cli::HelpTopic::Audit, "audit verify"),
        (cli::HelpTopic::Identity, "identity rotate"),
        (cli::HelpTopic::BreakGlass, "recover-controller"),
    ] {
        let help = help_text(topic);
        assert!(help.starts_with("Usage:") || help.starts_with("nazoauthctl"));
        assert!(help.contains(expected));
    }
}
