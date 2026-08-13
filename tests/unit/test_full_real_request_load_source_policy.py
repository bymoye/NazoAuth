#!/usr/bin/env python3
"""Static contracts for the destructive load-gate fixture boundary."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "full_real_request_load.py"


class FullRealRequestLoadPolicyTests(unittest.TestCase):
    def test_target_guard_rejects_local_or_external_targets(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"database_host": "nazo-oauth-e2e-postgres"', source)
        self.assertIn('"base_host": "nazo-oauth-e2e-server"', source)
        self.assertIn("refusing load seed outside Docker E2E targets", source)

    def test_target_guard_accepts_only_the_repository_e2e_target(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"database_port": 5432', source)
        self.assertIn('"base_port": 8000', source)

    def test_load_gate_always_runs_fixture_cleanup(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("def cleanup_load_fixture", source)
        self.assertIn("Load-gate fixture cleanup complete", source)
        self.assertIn("finally:", source)
        self.assertIn("cleanup_load_fixture()", source)
        self.assertIn('"admin_load_e2e_{LOAD_RUN_ID}"', source)
        self.assertIn('"Load Test Client {LOAD_RUN_ID}"', source)


if __name__ == "__main__":
    unittest.main()
