#!/usr/bin/env python3
"""Static regression tests for the RFC 9967 black-box boundary."""

from __future__ import annotations

import json
import importlib.util
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "rfc9967_scim_set_e2e.py"
MATRIX = ROOT / "tests" / "contracts" / "rfc9967-scim-set-matrix.json"
EXPECTED_CASES = {
    "discovery_exact_event_uris",
    "poll_authorization_boundaries",
    "create_notice_set_claims",
    "receiver_audience_and_ack_isolation",
    "ack_is_terminal_for_receiver",
    "set_error_requires_content_language",
    "patch_notice_and_deactivate_events",
    "put_notice_and_activate_events",
    "poll_pagination_preserves_order",
    "long_poll_wakes_on_new_event",
    "invalid_poll_shapes_fail_closed",
}


def load_runner_module():
    if str(RUNNER.parent) not in sys.path:
        sys.path.insert(0, str(RUNNER.parent))
    spec = importlib.util.spec_from_file_location("rfc9967_scim_set_e2e", RUNNER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Rfc9967BlackBoxPolicyTests(unittest.TestCase):
    def test_registry_is_exact_and_unique(self) -> None:
        payload = json.loads(MATRIX.read_text(encoding="utf-8"))
        names = [case["name"] for case in payload["cases"]]
        self.assertEqual(set(names), EXPECTED_CASES)
        self.assertEqual(len(names), len(EXPECTED_CASES))

    def test_runner_self_check_requires_no_runtime_dependencies(self) -> None:
        result = subprocess.run(
            [sys.executable, str(RUNNER), "--source-policy-check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_runner_cannot_observe_event_storage(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        forbidden = ("scim_security_" + "events", "scim_security_event_" + "receipts")
        for name in forbidden:
            self.assertNotIn(name, source)
        self.assertIn("INSERT INTO scim_tokens", source)
        self.assertIn("DELETE FROM scim_audit_events", source)
        self.assertIn("DELETE FROM scim_tokens", source)

    def test_destructive_target_guard_rejects_loopback_defaults(self) -> None:
        module = load_runner_module()
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(AssertionError):
                module.assert_destructive_targets_are_e2e()

    def test_destructive_target_guard_accepts_repository_e2e_target(self) -> None:
        module = load_runner_module()
        with (
            mock.patch.object(module, "BASE_URL", "http://nazo-oauth-e2e-server:8000"),
            mock.patch.object(
                module,
                "DATABASE_URL",
                "postgresql://postgres:postgres@nazo-oauth-e2e-postgres:5432/oauth",
            ),
        ):
            module.assert_destructive_targets_are_e2e()

    def test_cleanup_reports_http_or_database_failures(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("RFC 9967 cleanup incomplete", source)
        self.assertIn("RFC 9967 fixture cleanup complete", source)
        self.assertIn("finally:", source)

    def test_scim_tests_are_outside_production_sources(self) -> None:
        sources = [
            ROOT / "crates" / "scim-events" / "src" / "lib.rs",
            ROOT / "crates" / "http-actix" / "src" / "scim.rs",
        ]
        for path in sources:
            source = path.read_text(encoding="utf-8")
            self.assertNotIn("#[cfg(test)]", source, path)
            self.assertNotIn("mod tests", source, path)
        self.assertTrue((ROOT / "crates" / "scim-events" / "tests" / "domain_contract.rs").is_file())
        self.assertTrue((ROOT / "crates" / "http-actix" / "tests" / "scim_transport.rs").is_file())


if __name__ == "__main__":
    unittest.main()
