from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "scripts" / "deploy_live.ps1"


class DeployLiveWrapperContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = DEPLOY.read_text(encoding="utf-8")

    def test_wrapper_delegates_every_mutation_to_nazoauthctl(self) -> None:
        self.assertIn("'sudo', 'nazoauthctl', '--config'", self.source)
        for action in ("install", "update", "rollback", "recover"):
            self.assertIn(f"'{action}'", self.source)
        for forbidden in (
            "podman run",
            "docker run",
            "psql",
            "pg_restore",
            "nazoauth migrate",
            "nazoauth keyctl",
            "Remove-Item",
        ):
            self.assertNotIn(forbidden, self.source)

    def test_mutating_actions_use_formal_non_interactive_confirmation(self) -> None:
        self.assertIn("@('update', '--yes')", self.source)
        self.assertIn("@('rollback', '--yes')", self.source)
        self.assertIn("@('recover', '--yes')", self.source)
        self.assertIn("@('update', '--plan')", self.source)

    def test_default_action_is_read_only(self) -> None:
        self.assertIn("[string]$Action = 'status'", self.source)
        self.assertNotIn("[string]$Action = 'update'", self.source)

    def test_ssh_is_non_interactive_and_arguments_are_shell_quoted(self) -> None:
        self.assertIn("BatchMode=yes", self.source)
        self.assertIn("ConnectTimeout=15", self.source)
        self.assertIn("ConvertTo-ShellWord", self.source)
        self.assertIn("$remoteCommand", self.source)

    def test_remote_identity_inputs_are_fail_closed(self) -> None:
        self.assertIn("SshHost must be a configured SSH host alias", self.source)
        self.assertIn("Config must be a safe absolute remote path", self.source)
        self.assertIn("Version must be an immutable semantic tag", self.source)

    def test_wrapper_has_no_source_build_or_conformance_path(self) -> None:
        for forbidden in (
            "BackendCommit",
            "FrontendCommit",
            "cargo build",
            "docker build",
            "OIDF",
            "conformance",
        ):
            self.assertNotIn(forbidden, self.source)


if __name__ == "__main__":
    unittest.main()
