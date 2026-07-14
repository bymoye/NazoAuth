import http.client
import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


def load_runner_module():
    script = Path(__file__).resolve().parents[2] / "scripts" / "run_oidf_conformance.py"
    spec = importlib.util.spec_from_file_location("run_oidf_conformance", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class RunOidfConformanceTests(unittest.TestCase):
    def test_config_file_name_requires_json_extension(self):
        module = load_runner_module()

        module.validate_config_file_name("plan-config.json")
        with self.assertRaisesRegex(SystemExit, "must use the .json extension"):
            module.validate_config_file_name("plan-config.txt")
        for path_name in ("dir/plan-config.json", "dir\\plan-config.json"):
            with self.subTest(path_name=path_name):
                with self.assertRaisesRegex(SystemExit, "must be a file name"):
                    module.validate_config_file_name(path_name)

    def test_atomic_json_write_does_not_modify_hardlink_source(self):
        module = load_runner_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "outside.json"
            target = root / "target.json"
            outside.write_text("external inode\n", encoding="utf-8")
            os.link(outside, target)

            module.atomic_write_json_file(target, {"safe": True})

            self.assertEqual(outside.read_text(encoding="utf-8"), "external inode\n")
            self.assertEqual(target.read_text(encoding="utf-8"), '{\n  "safe": true\n}')
            self.assertNotEqual(os.stat(outside).st_ino, os.stat(target).st_ino)

    def test_atomic_json_write_replaces_symlink_without_following_it(self):
        module = load_runner_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "outside.json"
            target = root / "target.json"
            outside.write_text("external target\n", encoding="utf-8")
            target.write_text("safe at validation time\n", encoding="utf-8")
            self.assertTrue(target.is_file())
            self.assertFalse(target.is_symlink())
            target.unlink()
            try:
                target.symlink_to(outside)
            except OSError:
                target.write_text("simulated link directory entry\n", encoding="utf-8")
                real_replace = module.os.replace
                with mock.patch.object(
                    module.os,
                    "replace",
                    side_effect=lambda source, destination: real_replace(source, destination),
                ) as replace:
                    module.atomic_write_json_file(target, {"safe": True})
                replace.assert_called_once()
            else:
                self.assertTrue(target.is_symlink())
                module.atomic_write_json_file(target, {"safe": True})

            self.assertFalse(target.is_symlink())
            self.assertEqual(outside.read_text(encoding="utf-8"), "external target\n")
            self.assertEqual(target.read_text(encoding="utf-8"), '{\n  "safe": true\n}')

    def test_atomic_json_write_cleans_temporary_file_after_failure(self):
        module = load_runner_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.json"

            with (
                mock.patch.object(module.os, "replace", side_effect=OSError("replace failed")),
                self.assertRaisesRegex(OSError, "replace failed"),
            ):
                module.atomic_write_json_file(target, {"safe": True})

            self.assertEqual(list(root.iterdir()), [])

    def test_host_local_runner_applies_pinned_patch_before_execution(self):
        module = load_runner_module()
        suite_dir = Path("/tmp/oidf-suite")

        with mock.patch.object(module.subprocess, "run") as run:
            module.ensure_pinned_oidf_runner(suite_dir)

        command = run.call_args.args[0]
        self.assertEqual(command[0], module.sys.executable)
        self.assertTrue(command[1].endswith("apply_oidf_runner_patch.py"))
        self.assertEqual(command[2:], ["--suite-dir", str(suite_dir)])
        self.assertTrue(run.call_args.kwargs["check"])

    def test_official_runner_uses_isolated_bootstrap_and_sanitized_environment(self):
        module = load_runner_module()
        suite_scripts = Path("/trusted/suite/scripts")
        runner = suite_scripts / "run-test-plan.py"

        with mock.patch.dict(
            module.os.environ,
            {
                "PYTHONPATH": "/attacker",
                "PYTHONSTARTUP": "/attacker/sitecustomize.py",
                "SAFE_SETTING": "preserved",
            },
            clear=True,
        ):
            env = module.sanitized_runner_environment()
        command = module.official_runner_command(suite_scripts, runner)

        self.assertEqual(
            command[0:6],
            [module.sys.executable, "-I", "-S", "-B", "-u", "-c"],
        )
        self.assertIn("runpy.run_path", command[6])
        self.assertIn("sysconfig.get_paths", command[6])
        self.assertEqual(command[7:9], [str(suite_scripts), str(runner)])
        self.assertNotIn("PYTHONPATH", env)
        self.assertNotIn("PYTHONSTARTUP", env)
        self.assertNotIn("PYTHONUNBUFFERED", env)
        self.assertEqual(env["SAFE_SETTING"], "preserved")

    def test_isolated_bootstrap_does_not_run_attacker_sitecustomize_or_write_bytecode(self):
        module = load_runner_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            suite_scripts = root / "suite" / "scripts"
            attacker = root / "attacker"
            suite_scripts.mkdir(parents=True)
            attacker.mkdir()
            runner = suite_scripts / "run-test-plan.py"
            marker = root / "sitecustomize-ran"
            runner.write_text(
                "import sys\n"
                "assert 'sitecustomize' not in sys.modules\n"
                "assert sys.dont_write_bytecode\n",
                encoding="utf-8",
            )
            (attacker / "sitecustomize.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["PYTHONPATH"] = str(attacker)

            result = subprocess.run(
                module.official_runner_command(suite_scripts, runner),
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.exists())
            self.assertFalse((suite_scripts / "__pycache__").exists())

    def test_oidf_api_request_retries_remote_disconnect(self):
        module = load_runner_module()

        class FakeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            @staticmethod
            def read():
                return b'{"ok": true}'

        with (
            mock.patch.object(
                module.urllib.request,
                "urlopen",
                side_effect=[http.client.RemoteDisconnected("connection closed"), FakeResponse()],
            ) as urlopen,
            mock.patch.object(module.time, "sleep") as sleep,
        ):
            status, payload = module.oidf_api_request(
                "GET",
                "https://localhost:8443/",
                "api/server",
                None,
                expected_statuses={200},
            )

        self.assertEqual(status, 200)
        self.assertEqual(payload, {"ok": True})
        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once_with(2)

    def test_successful_completion_log_allows_browser_script_noise(self):
        module = load_runner_module()

        logs = [
            {"src": "BROWSER", "msg": "Error during JavaScript execution"},
            {"result": "SUCCESS", "src": "ValidateFrontchannelLogoutIss"},
            {"result": "FINISHED", "msg": "Test has run to completion"},
        ]

        self.assertIsNone(module.oidf_log_failure("module-id", logs))

    def test_successful_completion_log_does_not_hide_warning_or_failure(self):
        module = load_runner_module()

        logs = [
            {"result": "SUCCESS", "src": "ValidateFrontchannelLogoutIss"},
            {"result": "FAILURE", "src": "ValidatePostLogoutRedirect", "msg": "bad state"},
            {"result": "FINISHED", "msg": "Test has run to completion"},
        ]

        self.assertIn("FAILURE", module.oidf_log_failure("module-id", logs))

    def test_early_monitor_can_defer_result_failure_without_log_failure(self):
        module = load_runner_module()

        info = {
            "_id": "module-id",
            "testName": "oidcc-frontchannel-rp-initiated-logout",
            "status": "FINISHED",
            "result": "FAILED",
        }

        self.assertTrue(module.oidf_info_failure_can_wait_for_final_result(info))

    def test_early_monitor_does_not_defer_status_or_structured_errors(self):
        module = load_runner_module()

        self.assertFalse(
            module.oidf_info_failure_can_wait_for_final_result(
                {"status": "FAILED", "result": "FAILED"}
            )
        )
        self.assertFalse(
            module.oidf_info_failure_can_wait_for_final_result(
                {"status": "FINISHED", "result": "FAILED", "error": "runner crashed"}
            )
        )

    def test_review_allowlist_is_bound_to_config_alias(self):
        module = load_runner_module()
        aliases = {
            module.OIDCC_BASIC_CONFIG_FILE: "basic-alias",
            module.OIDCC_DYNAMIC_CONFIG_FILE: "dynamic-alias",
            module.FAPI_CONFIG_FILE: "fapi-alias",
        }
        allowlist = module.allowed_review_contexts_by_alias(aliases)
        review = {
            "_id": "module-id",
            "testName": "oidcc-prompt-login[variant=value]",
            "status": "FINISHED",
            "result": "REVIEW",
            "alias": "basic-alias",
        }

        self.assertIsNone(
            module.oidf_module_failure(
                review,
                allowlist,
                "oidcc-basic-certification-test-plan",
            )
        )
        self.assertIn(
            "result REVIEW",
            module.oidf_module_failure(review, allowlist, "different-test-plan"),
        )
        review["alias"] = "fapi-alias"
        self.assertIn(
            "result REVIEW",
            module.oidf_module_failure(
                review,
                allowlist,
                "oidcc-basic-certification-test-plan",
            ),
        )

    def test_unexpected_review_is_not_hidden_by_successful_completion_log(self):
        module = load_runner_module()
        info = {
            "_id": "module-id",
            "testName": "unexpected-review",
            "status": "FINISHED",
            "result": "REVIEW",
            "alias": "basic-alias",
        }
        logs = [
            {"result": "SUCCESS", "src": "Condition"},
            {"result": "FINISHED", "msg": "Test has run to completion"},
        ]

        with (
            mock.patch.object(
                module,
                "fetch_alias_plans",
                return_value=[
                    {
                        "_id": "plan-id",
                        "planName": "oidcc-basic-certification-test-plan",
                        "modules": [{"instances": ["module-id"]}],
                    }
                ],
            ),
            mock.patch.object(
                module,
                "oidf_api_request",
                side_effect=[(200, info), (200, logs)],
            ),
        ):
            failure = module.inspect_oidf_state(
                "https://suite.example",
                "token",
                {"basic-alias"},
                final=True,
                allowed_reviews_by_alias={
                    "basic-alias": (
                        "oidcc-basic-certification-test-plan",
                        frozenset({"oidcc-prompt-login"}),
                    )
                },
            )

        self.assertIn("unexpected-review", failure)

    def test_failed_result_is_not_hidden_by_successful_completion_log(self):
        module = load_runner_module()
        info = {
            "_id": "module-id",
            "testName": "failed-module",
            "status": "FINISHED",
            "result": "FAILED",
            "alias": "basic-alias",
        }
        logs = [
            {"result": "SUCCESS", "src": "Condition"},
            {"result": "FINISHED", "msg": "Test has run to completion"},
        ]

        with (
            mock.patch.object(
                module,
                "fetch_alias_plans",
                return_value=[
                    {
                        "_id": "plan-id",
                        "planName": "oidcc-basic-certification-test-plan",
                        "modules": [{"instances": ["module-id"]}],
                    }
                ],
            ),
            mock.patch.object(
                module,
                "oidf_api_request",
                side_effect=[(200, info), (200, logs)],
            ),
        ):
            failure = module.inspect_oidf_state(
                "https://suite.example",
                "token",
                {"basic-alias"},
                final=True,
            )

        self.assertIn("result FAILED", failure)

    def test_duplicate_allowed_review_exceeds_baseline(self):
        module = load_runner_module()
        plans = [
            {
                "_id": "plan-id",
                "planName": "oidcc-basic-certification-test-plan",
                "modules": [{"instances": ["module-a", "module-b"]}],
            }
        ]
        reviews = [
            {
                "_id": module_id,
                "testName": "oidcc-prompt-login",
                "status": "FINISHED",
                "result": "REVIEW",
                "alias": "basic-alias",
            }
            for module_id in ("module-a", "module-b")
        ]

        with (
            mock.patch.object(module, "fetch_alias_plans", return_value=plans),
            mock.patch.object(
                module,
                "oidf_api_request",
                side_effect=[
                    (200, reviews[0]),
                    (200, []),
                    (200, reviews[1]),
                ],
            ),
        ):
            failure = module.inspect_oidf_state(
                "https://suite.example",
                "token",
                {"basic-alias"},
                final=True,
                allowed_reviews_by_alias={
                    "basic-alias": (
                        "oidcc-basic-certification-test-plan",
                        frozenset({"oidcc-prompt-login"}),
                    )
                },
            )

        self.assertIn("baseline exceeded", failure)

    def test_ciba_backchannel_log_context_includes_sanitized_response_body(self):
        module = load_runner_module()

        context = module.oidf_log_context(
            [
                {
                    "src": "CallBackchannelAuthenticationEndpoint",
                    "result": "FAILURE",
                    "msg": "MalformedJsonException",
                    "args": {
                        "endpoint": "https://auth.nazo.run/bc-authorize?code=secret",
                        "body": "<html>token=secret</html>",
                        "response_status_code": 404,
                    },
                }
            ]
        )

        self.assertIn("CallBackchannelAuthenticationEndpoint", context)
        self.assertIn("https://auth.nazo.run/bc-authorize?redacted=1", context)
        self.assertIn("response_status_code=404", context)
        self.assertIn("token=<redacted>", context)
        self.assertNotIn("secret", context)

    def test_token_endpoint_log_context_includes_sanitized_response_body(self):
        module = load_runner_module()

        context = module.oidf_log_context(
            [
                {
                    "src": "CallTokenEndpointAndReturnFullResponse",
                    "msg": "HTTP response",
                    "args": {
                        "response_body": {
                            "error": "invalid_client",
                            "error_description": "token=secret",
                        },
                        "response_status_code": 401,
                    },
                }
            ]
        )

        self.assertIn("CallTokenEndpointAndReturnFullResponse", context)
        self.assertIn("invalid_client", context)
        self.assertIn("response_status_code=401", context)
        self.assertIn("token=<redacted>", context)
        self.assertNotIn("secret", context)

    def test_plan_expression_config_names_are_selected_exactly(self):
        module = load_runner_module()

        selected = module.config_names_from_plan_expressions(
            [
                "oidcc-basic-certification-test-plan[client_registration=static_client] oidf-oidcc-basic-plan-config.json",
                "oidcc-session-management-certification-test-plan[client_registration=static_client] oidf-oidcc-session-management-plan-config.json",
            ],
            {
                "oidf-oidcc-basic-plan-config.json",
                "oidf-oidcc-session-management-plan-config.json",
                "oidf-oidcc-frontchannel-logout-plan-config.json",
            },
        )

        self.assertEqual(
            selected,
            {
                "oidf-oidcc-basic-plan-config.json",
                "oidf-oidcc-session-management-plan-config.json",
            },
        )


if __name__ == "__main__":
    unittest.main()
