#!/usr/bin/env python3
"""Contracts for coverage phase isolation."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "generate_codecov_lcov.sh"


class CoveragePhaseIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SCRIPT.read_text(encoding="utf-8")

    def test_workspace_tests_use_separate_postgres_and_valkey_state(self) -> None:
        self.assertIn("CREATE DATABASE nazo_workspace_test", self.source)
        self.assertIn(
            'WORKSPACE_DATABASE_URL="postgresql://postgres:postgres@${POSTGRES_HOST}:${POSTGRES_PORT}/nazo_workspace_test"',
            self.source,
        )
        self.assertIn(
            'WORKSPACE_VALKEY_URL="redis://${VALKEY_HOST}:${VALKEY_PORT}/1"',
            self.source,
        )
        self.assertIn('export VALKEY_URL="redis://${VALKEY_HOST}:${VALKEY_PORT}/0"', self.source)
        self.assertIn('export NAZO_TEST_DATABASE_URL="$WORKSPACE_DATABASE_URL"', self.source)

    def test_workspace_state_switch_follows_e2e_and_precedes_workspace_tests(self) -> None:
        e2e = self.source.index('"$PYTHON_BIN" scripts/full_real_request_e2e.py')
        stop_server = self.source.index('SERVER_PID=""', e2e)
        switch_database = self.source.index(
            'export DATABASE_URL="$WORKSPACE_DATABASE_URL"', stop_server
        )
        migrate_workspace = self.source.index(
            "cargo test --locked -p nazo-postgres --test migrations", switch_database
        )
        run_workspace = self.source.index(
            "cargo test --locked --workspace --all-features --lib --bins --tests\n",
            migrate_workspace,
        )

        self.assertLess(e2e, stop_server)
        self.assertLess(stop_server, switch_database)
        self.assertLess(switch_database, migrate_workspace)
        self.assertLess(migrate_workspace, run_workspace)


if __name__ == "__main__":
    unittest.main()
