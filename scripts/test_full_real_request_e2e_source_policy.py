#!/usr/bin/env python3
"""Regression tests for the dependency-free real-HTTP source-policy gate."""

from __future__ import annotations

import ast
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from full_real_request_source_policy import RuntimeCaseEvidence, execute_case_registry


SCRIPT = Path(__file__).with_name("full_real_request_e2e.py")


class SourcePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.required = frozenset({"required_case"})
        self.registry = (("required_case", "handler", {}),)
        self.allowed = frozenset({"handler"})

    def run_registry(self, handler: object, evidence: RuntimeCaseEvidence | None = None) -> tuple[str, ...]:
        return execute_case_registry(
            self.registry,
            {"handler": handler},
            required=self.required,
            allowed_handlers=self.allowed,
            evidence=evidence or RuntimeCaseEvidence(self.required),
        )

    def test_real_case_assertion_is_required(self) -> None:
        with self.assertRaisesRegex(AssertionError, "did not assert"):
            self.run_registry(lambda _case, _params: None)
        with self.assertRaisesRegex(AssertionError, "did not assert"):
            self.run_registry(lambda case, _params: None if False else None)

    def test_wrong_and_duplicate_case_assertions_fail(self) -> None:
        evidence = RuntimeCaseEvidence(self.required | {"other_case"})
        with self.assertRaisesRegex(AssertionError, "wrong active case"):
            self.run_registry(lambda _case, _params: evidence.observe("other_case", True), evidence)

        evidence = RuntimeCaseEvidence(self.required)
        def duplicate(case: str, _params: dict[str, object]) -> None:
            evidence.observe(case, True)
            evidence.observe(case, True)
        with self.assertRaisesRegex(AssertionError, "duplicate runtime case assertion"):
            self.run_registry(duplicate, evidence)

    def test_registry_shape_and_handler_contract_failures_execute(self) -> None:
        evidence = RuntimeCaseEvidence(self.required)
        for registry, handlers, message in [
            ((), {"handler": lambda _case, _params: None}, "missing"),
            (self.registry + (("extra", "handler", {}),), {"handler": lambda _case, _params: None}, "extra"),
            (self.registry + self.registry, {"handler": lambda _case, _params: None}, "duplicates"),
            ((("required_case", "unknown", {}),), {}, "unknown_handlers"),
            (self.registry, {"handler": object()}, "not callable"),
        ]:
            with self.subTest(message=message), self.assertRaisesRegex(AssertionError, message):
                execute_case_registry(
                    registry,
                    handlers,
                    required=self.required,
                    allowed_handlers=self.allowed,
                    evidence=evidence,
                )

    def test_exception_cleans_active_state_and_next_run_succeeds(self) -> None:
        evidence = RuntimeCaseEvidence(self.required)
        with self.assertRaisesRegex(RuntimeError, "boom"):
            self.run_registry(lambda _case, _params: (_ for _ in ()).throw(RuntimeError("boom")), evidence)
        self.assertIsNone(evidence.active_case)
        executed = self.run_registry(lambda case, _params: evidence.observe(case, True), evidence)
        self.assertEqual(executed, ("required_case",))

    def test_nested_execution_cleans_state_and_next_run_succeeds(self) -> None:
        evidence = RuntimeCaseEvidence(self.required)

        def nested(_case: str, _params: dict[str, object]) -> None:
            execute_case_registry(
                self.registry,
                {"handler": lambda case, _params: evidence.observe(case, True)},
                required=self.required,
                allowed_handlers=self.allowed,
                evidence=evidence,
            )

        with self.assertRaisesRegex(AssertionError, "nested runtime case execution"):
            self.run_registry(nested, evidence)
        self.assertIsNone(evidence.active_case)
        executed = self.run_registry(lambda case, _params: evidence.observe(case, True), evidence)
        self.assertEqual(executed, ("required_case",))

    def test_handler_map_missing_and_extra_keys_fail(self) -> None:
        evidence = RuntimeCaseEvidence(self.required)
        with self.assertRaisesRegex(AssertionError, "handler map is not exact"):
            execute_case_registry(
                self.registry,
                {},
                required=self.required,
                allowed_handlers=self.allowed,
                evidence=evidence,
            )
        with self.assertRaisesRegex(AssertionError, "handler map is not exact"):
            execute_case_registry(
                self.registry,
                {
                    "handler": lambda case, _params: evidence.observe(case, True),
                    "extra_handler": lambda _case, _params: None,
                },
                required=self.required,
                allowed_handlers=self.allowed,
                evidence=evidence,
            )

    def test_policy_self_tests_reject_dead_or_non_registry_evidence(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--source-policy-self-test"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_live_source_policy_accepts_executable_registry(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--source-policy-check"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_private_key_jwt_fixtures_explicitly_opt_into_endpoint_audience(self) -> None:
        expected_clients = {
            "Private JWT Full E2E",
            "Private JWT Multi Alg Full E2E",
            "Private JWT Auth Code Full E2E",
            "Private JWT DPoP Required Full E2E",
        }
        configured_clients: dict[str, object] = {}

        for node in ast.walk(ast.parse(SCRIPT.read_text(encoding="utf-8"))):
            if (
                not isinstance(node, ast.Call)
                or not isinstance(node.func, ast.Name)
                or node.func.id != "create_client"
                or len(node.args) < 2
                or not isinstance(node.args[1], ast.Dict)
            ):
                continue

            fields: dict[str, object] = {}
            for key, value in zip(node.args[1].keys, node.args[1].values, strict=True):
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    if isinstance(value, ast.Constant):
                        fields[key.value] = value.value
            if fields.get("token_endpoint_auth_method") == "private_key_jwt":
                client_name = fields.get("client_name")
                self.assertIsInstance(client_name, str)
                configured_clients[str(client_name)] = fields.get(
                    "allow_client_assertion_endpoint_audience"
                )

        self.assertEqual(set(configured_clients), expected_clients)
        self.assertTrue(all(value is True for value in configured_clients.values()))


if __name__ == "__main__":
    unittest.main()
