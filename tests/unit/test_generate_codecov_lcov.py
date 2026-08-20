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

    def test_workspace_state_switch_follows_server_shutdown_and_precedes_workspace_tests(self) -> None:
        server_start = self.source.index('SERVER_PID=$!')
        stop_server = self.source.index('SERVER_PID=""', server_start)
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

        self.assertLess(server_start, stop_server)
        self.assertLess(stop_server, switch_database)
        self.assertLess(switch_database, migrate_workspace)
        self.assertLess(migrate_workspace, run_workspace)

    def test_live_protocol_coverage_uses_an_explicit_local_service_allowlist(self) -> None:
        workspace_tests = self.source.index(
            "cargo test --locked --workspace --all-features --lib --bins --tests\n"
        )
        live_tests = self.source.index("COVERAGE_LIVE_TESTS=(", workspace_tests)
        coverage_export = self.source.index("test_objects=()", live_tests)

        for test_name in (
            "live_immediate_offer_pre_authorized_credential_replay_and_notification",
            "live_deferred_credential_claim_response_replay_and_notification",
            "live_access_enforces_dpop_binding_and_validates_presented_proof",
            "live_offer_enforces_subject_dataset_lifetime_and_transaction_code_policy",
            "par_fapi2_rejects_shared_secret_client_auth_after_authentication",
        ):
            self.assertIn(test_name, self.source[live_tests:coverage_export])
        self.assertIn(
            'cargo test --locked -p nazo-oauth-server --lib "$test_name" -- --ignored',
            self.source[live_tests:coverage_export],
        )
        self.assertLess(workspace_tests, live_tests)
        self.assertLess(live_tests, coverage_export)

    def test_coverage_exports_cargo_artifacts_and_uses_the_host_executable_suffix(self) -> None:
        self.assertIn('*-windows-*) EXECUTABLE_SUFFIX=".exe" ;;', self.source)
        self.assertIn('SERVER_BIN="$BIN_DIR/nazoauth$EXECUTABLE_SUFFIX"', self.source)
        self.assertIn('TEST_OBJECT_MANIFEST="$COVERAGE_DIR/test-objects.jsonl"', self.source)
        self.assertIn('sys.stdout.buffer.write(payload.encode("utf-8") + b"\\n")', self.source)
        self.assertIn('"$object" > "$test_report"', self.source)
        self.assertIn('PRIMARY_SERVER_PORT="${CODECOV_PRIMARY_SERVER_PORT:-18000}"', self.source)
        self.assertIn('SIGNED_SERVER_PORT="${CODECOV_SIGNED_SERVER_PORT:-18001}"', self.source)
        self.assertIn('listener.bind(("127.0.0.1", int(raw_port)))', self.source)
        self.assertIn('BIND="127.0.0.1:${SIGNED_SERVER_PORT}"', self.source)
        self.assertNotIn("cargo llvm-cov report", self.source)
        self.assertNotIn("lcov-workspace-tests.info", self.source)

    def test_parallel_server_instances_use_distinct_identity_directories(self) -> None:
        self.assertIn(
            'PRIMARY_INSTANCE_IDENTITY_DIR="$SCRIPT_ROOT/runtime/codecov/instance-primary"',
            self.source,
        )
        self.assertIn(
            'SIGNED_INSTANCE_IDENTITY_DIR="$SCRIPT_ROOT/runtime/codecov/instance-signed"',
            self.source,
        )
        self.assertIn('INSTANCE_IDENTITY_DIR="$PRIMARY_INSTANCE_IDENTITY_DIR"', self.source)
        self.assertIn('INSTANCE_IDENTITY_DIR="$SIGNED_INSTANCE_IDENTITY_DIR"', self.source)
        self.assertLess(
            self.source.index('INSTANCE_IDENTITY_DIR="$PRIMARY_INSTANCE_IDENTITY_DIR"'),
            self.source.index('INSTANCE_IDENTITY_DIR="$SIGNED_INSTANCE_IDENTITY_DIR"'),
        )

    def test_destructive_container_names_are_not_environment_selectable(self) -> None:
        self.assertIn("DEFAULT_POSTGRES_CONTAINER=\"nazo-oauth-codecov-postgres\"", self.source)
        self.assertIn("DEFAULT_VALKEY_CONTAINER=\"nazo-oauth-codecov-valkey\"", self.source)
        self.assertIn("refusing CODECOV_POSTGRES_CONTAINER override", self.source)
        self.assertIn("refusing CODECOV_VALKEY_CONTAINER override", self.source)

    def test_cargo_target_dir_is_pinned_to_repository_owned_coverage_root(self) -> None:
        self.assertIn("realpath -m", self.source)
        self.assertIn("DEFAULT_CARGO_TARGET_DIR=\"$SCRIPT_ROOT/target/codecov-coverage\"", self.source)
        self.assertIn("refusing CARGO_TARGET_DIR outside the repository-owned codecov target", self.source)

    def test_docker_network_override_is_rejected(self) -> None:
        self.assertIn("refusing CODECOV_DOCKER_NETWORK override", self.source)
        self.assertNotIn('DOCKER_NETWORK="${CODECOV_DOCKER_NETWORK:-}"', self.source)

    def test_cleanup_removes_only_labelled_script_owned_containers(self) -> None:
        self.assertIn("remove_owned_container", self.source)
        self.assertIn("refusing to remove unowned Docker container", self.source)
        self.assertIn("io.nazoauth.owner=$CODECOV_OWNER_LABEL", self.source)


if __name__ == "__main__":
    unittest.main()
