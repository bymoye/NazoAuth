use std::process::Command;

use super::AUTHENTICATED_VALKEY_COMMAND;

#[test]
fn authenticated_valkey_command_does_not_forward_the_password_path() {
    let command = AUTHENTICATED_VALKEY_COMMAND.replace("valkey-cli", "valkey_cli");
    let script = format!("valkey_cli() {{ printf '%s\\n' \"$@\"; }}; {command}");
    let output = Command::new("sh")
        .args(["-eu", "-c", &script, "_", "/dev/null", "LASTSAVE", "EXTRA"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "--askpass\nLASTSAVE\nEXTRA\n"
    );
    assert!(output.stderr.is_empty());
}
