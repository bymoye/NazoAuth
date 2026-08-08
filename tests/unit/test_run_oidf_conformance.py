import http.client
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import types
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
    def test_private_plan_config_has_no_environment_fallback(self):
        module = load_runner_module()
        source = Path(module.__file__).read_text(encoding="utf-8")
        self.assertNotIn('parser.add_argument("--config-env"', source)
        self.assertNotIn("OIDF_PLAN_CONFIG_JSON", source)

    def test_ciba_automation_gate_reads_the_required_private_config_file(self):
        module = load_runner_module()
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "configs": {
                            "ciba": {
                                "alias": "nazo-oauth-oidf-fapi-ciba-private-poll",
                                "automated_ciba_approval_url": "https://issuer.example/test/ciba",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            self.assertTrue(module.ciba_config_has_automated_approval_url(str(config)))

    def test_ciba_automation_gate_rejects_a_config_without_approval_url(self):
        module = load_runner_module()
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "config.json"
            config.write_text(
                json.dumps({"configs": {"ciba": {"alias": "nazo-oauth-oidf-fapi-ciba"}}}),
                encoding="utf-8",
            )

            self.assertFalse(module.ciba_config_has_automated_approval_url(str(config)))

    def test_runtime_secret_environment_cannot_override_private_plan_credentials(self):
        module = load_runner_module()
        config = {
            "nazo": {
                "oidf_user_email": "stale@example.test",
                "oidf_user_password": "stale-password",
            }
        }

        with mock.patch.dict(
            module.os.environ,
            {
                "OIDF_USER_EMAIL": "current@example.test",
                "OIDF_USER_PASSWORD": "current-password",
            },
        ):
            credentials = module.nazo_automation_credentials(config)

        self.assertEqual(credentials, ("stale@example.test", "stale-password"))

    def test_plan_config_credentials_remain_available_for_local_runs(self):
        module = load_runner_module()
        config = {
            "nazo": {
                "oidf_user_email": "local@example.test",
                "oidf_user_password": "local-password",
            }
        }

        with mock.patch.dict(module.os.environ, {}, clear=True):
            credentials = module.nazo_automation_credentials(config)

        self.assertEqual(credentials, ("local@example.test", "local-password"))

    def test_private_plan_configs_are_restored_or_removed_after_materialization(self):
        module = load_runner_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            suite_scripts = root / "suite" / "scripts"
            suite_scripts.mkdir(parents=True)
            private_input = root / "private.json"
            private_input.write_text(
                json.dumps({"configs": {"existing.json": {"alias": "private-alias"}}}),
                encoding="utf-8",
            )
            if os.name != "nt":
                private_input.chmod(0o600)
            existing = suite_scripts / "existing.json"
            existing.write_bytes(b"suite-owned-before-run\n")
            original_mode = existing.stat().st_mode & 0o777
            backups = {}

            with mock.patch.object(
                module,
                "read_private_text",
                return_value=private_input.read_text(encoding="utf-8"),
            ):
                module.write_plan_configs(
                    suite_scripts,
                    "ignored.json",
                    str(private_input),
                    "",
                    backups=backups,
                )
            module.restore_plan_configs(backups)

            self.assertEqual(existing.read_bytes(), b"suite-owned-before-run\n")
            self.assertEqual(existing.stat().st_mode & 0o777, original_mode)
            self.assertFalse((suite_scripts / "ignored.json").exists())

    def test_main_source_has_finally_cleanup_for_injected_configs(self):
        module = load_runner_module()
        source = Path(module.__file__).read_text(encoding="utf-8")
        self.assertIn("plan_config_backups", source)
        self.assertIn("restore_plan_configs(plan_config_backups)", source)
        self.assertIn("OIDF conformance cleanup incomplete", source)

    def test_main_accepts_omitted_expected_skips_file(self):
        module = load_runner_module()
        with tempfile.TemporaryDirectory() as temporary:
            suite_dir = Path(temporary)
            scripts_dir = suite_dir / "scripts"
            scripts_dir.mkdir()
            (scripts_dir / "run-test-plan.py").touch()
            args = types.SimpleNamespace(
                rerun=None,
                disable_ssl_verify=False,
                target_issuer="https://issuer.example",
                suite_dir=str(suite_dir),
                suite_revision="revision",
                config_file_name="config.json",
                config_json_file=None,
                plan_expression=[],
                plan_set_env="PLAN_SET",
                plan_set_json_file=None,
                conformance_server="https://suite.example",
                no_api_token=True,
                token_fd=None,
                token_file=None,
                list=False,
                no_parallel=False,
                expected_failures_file=None,
                expected_skips_file=None,
                export_dir=None,
                verbose=False,
                timeout_seconds=30,
                monitor_interval_seconds=10,
            )

            with (
                mock.patch.object(module, "parse_args", return_value=args),
                mock.patch.object(module, "verify_pristine_oidf_suite"),
                mock.patch.object(
                    module,
                    "write_plan_configs",
                    return_value=({"config.json"}, {"config.json": "alias"}),
                ),
                mock.patch.object(module, "plan_expressions", return_value=["plan config.json"]),
                mock.patch.object(module, "cleanup_existing_alias_plans"),
                mock.patch.object(module, "run_official_runner", return_value=0) as run,
            ):
                self.assertEqual(module.main(), 0)

        self.assertEqual(run.call_args.args[-2], {})
        self.assertIsNone(run.call_args.args[-1])

    def test_official_runner_terminates_nested_process_group_when_interrupted(self):
        module = load_runner_module()

        class Process:
            pid = 4321

            def wait(self, timeout=None):
                raise KeyboardInterrupt

        process = Process()
        with (
            mock.patch.object(module.subprocess, "Popen", return_value=process) as popen,
            mock.patch.object(module, "terminate_runner") as terminate,
            self.assertRaises(KeyboardInterrupt),
        ):
            module.run_official_runner(
                ["runner"],
                [],
                Path("."),
                {},
                30,
                "https://suite.example/",
                set(),
                None,
                0,
                {},
                {},
                {},
                None,
            )

        terminate.assert_called_once_with(process)
        self.assertIs(popen.call_args.kwargs["stdout"], module.subprocess.DEVNULL)
        self.assertIs(popen.call_args.kwargs["stderr"], module.subprocess.DEVNULL)

    def test_callback_completion_waits_have_a_thirty_second_floor(self):
        module = load_runner_module()
        value = {
            "tasks": [
                {"commands": [["wait", "id", "submission_complete", 10]]},
                {"commands": [["wait", "id", "submission_complete", 60]]},
            ]
        }

        module.normalize_oidf_callback_waits_in_value(value, "/test/a/alias/callback")

        waits = [task["commands"][0][3] for task in value["tasks"]]
        self.assertEqual(waits, [30, 60])
        self.assertEqual(
            module.nazo_consent_approve_commands({})[-1][3],
            module.OIDF_BROWSER_CALLBACK_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            module.nazo_consent_deny_commands({})[-1][3],
            module.OIDF_BROWSER_CALLBACK_TIMEOUT_SECONDS,
        )

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

    def test_host_local_runner_requires_exact_pristine_official_checkout(self):
        module = load_runner_module()
        suite_dir = Path("/tmp/oidf-suite")

        with mock.patch.object(
            module.subprocess,
            "run",
            side_effect=[
                mock.Mock(stdout="expected-revision\n"),
                mock.Mock(stdout=""),
            ],
        ) as run:
            module.verify_pristine_oidf_suite(suite_dir, "expected-revision")

        self.assertEqual(
            run.call_args_list[0].args[0],
            ["git", "-C", str(suite_dir), "rev-parse", "HEAD"],
        )
        self.assertIn("--untracked-files=no", run.call_args_list[1].args[0])

    def test_host_local_runner_rejects_modified_official_checkout(self):
        module = load_runner_module()
        with (
            mock.patch.object(
                module.subprocess,
                "run",
                side_effect=[
                    mock.Mock(stdout="expected-revision\n"),
                    mock.Mock(stdout=" M scripts/run-test-plan.py\n"),
                ],
            ),
            self.assertRaises(SystemExit),
        ):
            module.verify_pristine_oidf_suite(Path("/tmp/oidf-suite"), "expected-revision")

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
        command = module.official_runner_command(suite_scripts, runner, None)

        self.assertEqual(
            command[0:6],
            [module.sys.executable, "-I", "-S", "-B", "-u", "-c"],
        )
        self.assertIn("runpy.run_path", command[6])
        self.assertTrue(command[7].endswith("oidf_fd_bootstrap.py"))
        self.assertEqual(command[8:11], [str(suite_scripts), str(runner), "-"])
        self.assertNotIn("PYTHONPATH", env)

        bootstrap = Path(command[7]).read_text(encoding="utf-8")
        self.assertIn("sysconfig.get_paths", bootstrap)
        self.assertIn("class OneShotSecretEnvironment", bootstrap)
        self.assertNotIn("os.environ.__setitem__", bootstrap)
        self.assertNotIn("PYTHONSTARTUP", env)
        self.assertNotIn("PYTHONUNBUFFERED", env)
        self.assertNotIn("SAFE_SETTING", env)

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
                module.official_runner_command(suite_scripts, runner, None),
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.exists())
            self.assertFalse((suite_scripts / "__pycache__").exists())

    def test_fd_bootstrap_token_is_one_shot_and_absent_from_copies(self):
        bootstrap_path = (
            Path(__file__).resolve().parents[2] / "scripts" / "oidf_fd_bootstrap.py"
        )
        spec = importlib.util.spec_from_file_location("oidf_fd_bootstrap_test", bootstrap_path)
        bootstrap = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(bootstrap)

        environment = bootstrap.OneShotSecretEnvironment(
            {"PATH": os.environ.get("PATH", "")}, bytearray(b"one-shot-token")
        )
        self.assertNotIn("CONFORMANCE_TOKEN", environment)
        self.assertNotIn("CONFORMANCE_TOKEN", environment.copy())
        self.assertEqual(environment["CONFORMANCE_TOKEN"], "one-shot-token")
        with self.assertRaises(KeyError):
            _ = environment["CONFORMANCE_TOKEN"]

        child = subprocess.check_output(
            [
                sys.executable,
                "-c",
                "import os;print(os.environ.get('CONFORMANCE_TOKEN','absent'))",
            ],
            env=environment.copy(),
            text=True,
        )
        self.assertEqual(child.strip(), "absent")

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux /proc and pass_fds")
    def test_token_fd_is_absent_from_proc_environment_and_descendants(self):
        module = load_runner_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            suite_scripts = root / "suite" / "scripts"
            suite_scripts.mkdir(parents=True)
            runner = suite_scripts / "run-test-plan.py"
            runner.write_text(
                "import os,subprocess,sys\n"
                "token=os.environ['CONFORMANCE_TOKEN']\n"
                "assert token == 'fd-only-test-token'\n"
                "assert 'CONFORMANCE_TOKEN' not in os.environ\n"
                "assert b'fd-only-test-token' not in open('/proc/self/environ','rb').read()\n"
                "child=subprocess.check_output([sys.executable,'-c',"
                "\"import os;print(os.environ.get('CONFORMANCE_TOKEN','absent'))\"])\n"
                "assert child.strip() == b'absent'\n",
                encoding="utf-8",
            )
            reader, writer = os.pipe()
            try:
                os.write(writer, b"fd-only-test-token")
            finally:
                os.close(writer)
            try:
                result = subprocess.run(
                    module.official_runner_command(suite_scripts, runner, reader),
                    pass_fds=(reader,),
                    check=False,
                    capture_output=True,
                    text=True,
                    env=module.sanitized_runner_environment(),
                )
            finally:
                os.close(reader)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_oidf_api_request_retries_remote_disconnect(self):
        module = load_runner_module()

        class FakeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            @staticmethod
            def read(_size=-1):
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

    def test_oidf_api_request_retries_transient_server_error(self):
        module = load_runner_module()

        class FakeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            @staticmethod
            def read(_size=-1):
                return b'{"ok": true}'

        error = module.urllib.error.HTTPError(
            "https://localhost:8443/api/log/module",
            503,
            "Service Unavailable",
            {},
            None,
        )

        with (
            mock.patch.object(
                module.urllib.request,
                "urlopen",
                side_effect=[error, FakeResponse()],
            ) as urlopen,
            mock.patch.object(module.time, "sleep") as sleep,
        ):
            status, payload = module.oidf_api_request(
                "GET",
                "https://localhost:8443/",
                "api/log/module",
                None,
                expected_statuses={200},
            )

        self.assertEqual(status, 200)
        self.assertEqual(payload, {"ok": True})
        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once_with(2)

    def test_oidf_api_request_rejects_empty_success_payload(self):
        module = load_runner_module()

        class FakeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            @staticmethod
            def read(_size=-1):
                return b""

        with mock.patch.object(module.urllib.request, "urlopen", return_value=FakeResponse()):
            with self.assertRaisesRegex(SystemExit, "empty HTTP 200"):
                module.oidf_api_request(
                    "GET",
                    "https://localhost:8443/",
                    "api/server",
                    None,
                    expected_statuses={200},
                )

    def test_oidf_api_request_rejects_invalid_success_json(self):
        module = load_runner_module()

        class FakeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            @staticmethod
            def read(_size=-1):
                return b"not-json"

        with mock.patch.object(module.urllib.request, "urlopen", return_value=FakeResponse()):
            with self.assertRaisesRegex(SystemExit, "invalid JSON for HTTP 200"):
                module.oidf_api_request(
                    "GET",
                    "https://localhost:8443/",
                    "api/server",
                    None,
                    expected_statuses={200},
                )

    def test_oidf_api_request_rejects_oversized_response(self):
        module = load_runner_module()

        class FakeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self, size=-1):
                self.requested_size = size
                return b"x" * (module.MAX_OIDF_API_RESPONSE_BYTES + 1)

        with mock.patch.object(module.urllib.request, "urlopen", return_value=FakeResponse()):
            with self.assertRaisesRegex(SystemExit, "response exceeds 1 MiB"):
                module.oidf_api_request(
                    "GET",
                    "https://localhost:8443/",
                    "api/server",
                    None,
                    expected_statuses={200},
                )

    def test_fetch_alias_plans_rejects_malformed_success_schema(self):
        module = load_runner_module()
        with mock.patch.object(module, "oidf_api_request", return_value=(200, [])):
            with self.assertRaisesRegex(SystemExit, "non-object JSON payload"):
                module.fetch_alias_plans("https://suite.example", "token", {"alias"})

    def test_inspect_state_rejects_empty_success_module_info(self):
        module = load_runner_module()
        with (
            mock.patch.object(
                module,
                "fetch_alias_plans",
                return_value=[
                    {
                        "_id": "plan-id",
                        "planName": "oid4vci-1_0-issuer-test-plan",
                        "modules": [{"instances": ["module-id"]}],
                    }
                ],
            ),
            mock.patch.object(module, "oidf_api_request", return_value=(200, None)),
        ):
            failure = module.inspect_oidf_state(
                "https://suite.example",
                "token",
                {"alias"},
                final=True,
            )

        self.assertIn("invalid HTTP 200 module info payload", failure)

    def test_monitor_interval_has_floor_when_aliases_are_present(self):
        module = load_runner_module()

        self.assertEqual(
            module.effective_monitor_interval_seconds({"oidf-alias"}, 0),
            60,
        )
        self.assertEqual(
            module.effective_monitor_interval_seconds({"oidf-alias"}, 30),
            30,
        )
        self.assertEqual(module.effective_monitor_interval_seconds(set(), 0), 0)

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

    def test_inspect_state_reports_precise_early_warning_block_despite_later_log_noise(self):
        module = load_runner_module()
        info = {
            "_id": "module-id",
            "alias": "vci-alias",
            "testName": "fapi2-security-profile-final-dpop-negative-tests",
            "status": "FINISHED",
            "result": "WARNING",
        }
        logs = [
            {
                "blockId": "replay",
                "startBlock": True,
                "msg": "DPoP reuse, Second use of the same jti, this 'should' fail",
            },
            {
                "blockId": "replay",
                "result": "WARNING",
                "src": "EnsureHttpStatusCodeIs400or401",
                "msg": "resource endpoint returned a different http status than expected",
            },
            *[
                {
                    "src": "WebRunner",
                    "msg": f"later browser log {index}",
                    "result": "INFO",
                }
                for index in range(10)
            ],
        ]

        with (
            mock.patch.object(
                module,
                "fetch_alias_plans",
                return_value=[
                    {
                        "_id": "plan-id",
                        "planName": "oid4vci-1_0-issuer-test-plan",
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
                {"vci-alias"},
                final=True,
            )

        self.assertIn("EnsureHttpStatusCodeIs400or401", failure)
        self.assertIn("DPoP reuse, Second use of the same jti", failure)
        self.assertIn("resource endpoint returned a different http status", failure)

    def test_expected_tls_warning_requires_exact_alias_variant_module_block_and_condition(self):
        module = load_runner_module()
        info = {
            "alias": "ping-alias",
            "testName": "fapi-ciba-id1",
            "variant": {
                "client_auth_type": "mtls",
                "ciba_mode": "ping",
                "fapi_ciba_profile": "plain_fapi",
                "client_registration": "static_client",
            },
        }
        logs = [
            {"blockId": "tls", "startBlock": True, "msg": "Verify notification callback"},
            {
                "blockId": "tls",
                "result": "WARNING",
                "src": "EnsureIncomingTls13",
                "msg": "Client doesn't support TLS 1.3",
            },
        ]
        context = (
            "warning",
            "fapi-ciba-id1",
            tuple(sorted(info["variant"].items())),
            "Verify notification callback",
            "EnsureIncomingTls13",
        )
        allowed = {"ping-alias": frozenset({context})}

        self.assertIsNone(
            module.oidf_log_failure(
                "module-id",
                logs,
                info=info,
                allowed_expected_problems_by_alias=allowed,
            )
        )
        self.assertTrue(module.oidf_log_has_allowed_expected_problem(info, logs, allowed))
        logs[1]["src"] = "DifferentCondition"
        self.assertIn(
            "WARNING",
            module.oidf_log_failure(
                "module-id",
                logs,
                info=info,
                allowed_expected_problems_by_alias=allowed,
            ),
        )

    def test_expected_skip_is_scoped_to_alias_test_and_optional_exact_variant(self):
        module = load_runner_module()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "skips.json"
            path.write_text(
                json.dumps(
                    [
                        {
                            "configuration-filename": "dynamic.json",
                            "test-name": "oidcc-idtoken-unsigned",
                            "variant": "*",
                        },
                        {
                            "configuration-filename": "static.json",
                            "test-name": "exact-module",
                            "variant": {"response_type": "code"},
                        },
                    ]
                ),
                encoding="utf-8",
            )
            allowed = module.expected_skip_contexts_by_alias(
                path,
                {"dynamic.json": "dynamic-alias", "static.json": "static-alias"},
            )

        self.assertTrue(
            module.is_allowed_expected_skip(
                {
                    "alias": "dynamic-alias",
                    "testName": "oidcc-idtoken-unsigned[response_type=code]",
                    "variant": {"response_type": "code"},
                },
                allowed,
            )
        )
        self.assertTrue(
            module.is_allowed_expected_skip(
                {
                    "alias": "static-alias",
                    "testName": "exact-module",
                    "variant": {"response_type": "code"},
                },
                allowed,
            )
        )
        self.assertFalse(
            module.is_allowed_expected_skip(
                {
                    "alias": "static-alias",
                    "testName": "exact-module",
                    "variant": {"response_type": "id_token"},
                },
                allowed,
            )
        )
    def test_expected_warning_accepts_oidf_start_block_log_marker(self):
        module = load_runner_module()
        info = {
            "alias": "vci-alias",
            "testName": "fapi2-security-profile-final-refresh-token",
            "variant": {
                "client_auth_type": "client_attestation",
                "fapi_profile": "vci_haip",
                "vci_grant_type": "authorization_code",
            },
        }
        logs = [
            {
                "blockId": "refresh-token",
                "src": "-START-BLOCK-",
                "msg": "Check for refresh token",
            },
            {
                "blockId": "refresh-token",
                "result": "WARNING",
                "src": "FAPIEnsureServerConfigurationDoesNotSupportRefreshToken",
                "msg": "The server configuration supports refresh tokens.",
            },
        ]
        context = (
            "warning",
            "fapi2-security-profile-final-refresh-token",
            tuple(sorted(info["variant"].items())),
            "Check for refresh token",
            "FAPIEnsureServerConfigurationDoesNotSupportRefreshToken",
        )
        allowed = {"vci-alias": frozenset({context})}

        self.assertIsNone(
            module.oidf_log_failure(
                "module-id",
                logs,
                info=info,
                allowed_expected_problems_by_alias=allowed,
            )
        )
        self.assertTrue(module.oidf_log_has_allowed_expected_problem(info, logs, allowed))

    def test_inspect_state_applies_expected_warning_context_to_final_log_scan(self):
        module = load_runner_module()
        info = {
            "_id": "module-id",
            "alias": "vci-alias",
            "testName": "fapi2-security-profile-final-refresh-token",
            "status": "FINISHED",
            "result": "PASSED",
            "variant": {
                "client_auth_type": "client_attestation",
                "fapi_profile": "vci_haip",
                "vci_grant_type": "authorization_code",
            },
        }
        logs = [
            {
                "blockId": "refresh-token",
                "src": "-START-BLOCK-",
                "msg": "Check for refresh token",
            },
            {
                "blockId": "refresh-token",
                "result": "WARNING",
                "src": "FAPIEnsureServerConfigurationDoesNotSupportRefreshToken",
                "msg": "The server configuration supports refresh tokens.",
            },
        ]
        context = (
            "warning",
            "fapi2-security-profile-final-refresh-token",
            tuple(sorted(info["variant"].items())),
            "Check for refresh token",
            "FAPIEnsureServerConfigurationDoesNotSupportRefreshToken",
        )

        with (
            mock.patch.object(
                module,
                "fetch_alias_plans",
                return_value=[
                    {
                        "_id": "plan-id",
                        "planName": "oid4vci-1_0-issuer-test-plan",
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
                {"vci-alias"},
                final=True,
                allowed_expected_problems_by_alias={"vci-alias": frozenset({context})},
            )

        self.assertIsNone(failure)

    def test_expected_tls_warning_file_rejects_wildcards(self):
        module = load_runner_module()
        payload = [
            {
                "test-name": "fapi-ciba-id1*",
                "variant": {"client_auth_type": "mtls"},
                "configuration-filename": "ping.json",
                "current-block": "Verify notification callback",
                "condition": "EnsureIncomingTls13",
                "expected-result": "warning",
            }
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "warnings.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(SystemExit):
                module.expected_problem_contexts_by_alias(path, {"ping.json": "ping-alias"})

    def test_inspect_state_accepts_an_exact_expected_failure(self):
        module = load_runner_module()
        variant = {
            "credential_format": "sd_jwt_vc",
            "vci_grant_type": "pre_authorization_code",
        }
        info = {
            "_id": "module-id",
            "alias": "vci-alias",
            "testName": "oid4vci-1_0-issuer-happy-flow-multiple-clients",
            "status": "FINISHED",
            "result": "FAILED",
            "variant": variant,
        }
        logs = [
            {
                "blockId": "second-client-token",
                "src": "-START-BLOCK-",
                "msg": "Second client: Verify token endpoint response",
            },
            {
                "blockId": "second-client-token",
                "result": "FAILURE",
                "src": "CheckTokenEndpointHttpStatus200",
                "msg": "Invalid http status",
            },
        ]
        context = (
            "failure",
            info["testName"],
            tuple(sorted(variant.items())),
            "Second client: Verify token endpoint response",
            "CheckTokenEndpointHttpStatus200",
        )

        with (
            mock.patch.object(
                module,
                "fetch_alias_plans",
                return_value=[
                    {
                        "_id": "plan-id",
                        "planName": "oid4vci-1_0-issuer-test-plan",
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
                {"vci-alias"},
                final=True,
                allowed_expected_problems_by_alias={
                    "vci-alias": frozenset({context})
                },
            )

        self.assertIsNone(failure)

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
            module.OIDCC_FORMPOST_CONFIG_FILE: "formpost-alias",
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
        review["alias"] = "formpost-alias"
        self.assertIsNone(
            module.oidf_module_failure(
                review,
                allowlist,
                "oidcc-formpost-basic-certification-test-plan",
            )
        )
        self.assertIn(
            "result REVIEW",
            module.oidf_module_failure(
                review,
                allowlist,
                "oidcc-basic-certification-test-plan",
            ),
        )

    def test_rp_initiated_review_allowlist_matches_the_eight_screenshot_modules(self):
        module = load_runner_module()

        plan, modules = module.OIDF_ALLOWED_REVIEW_CONTEXTS_BY_CONFIG[
            module.OIDCC_RP_INITIATED_LOGOUT_CONFIG_FILE
        ]

        self.assertEqual(plan, "oidcc-rp-initiated-logout-certification-test-plan")
        self.assertEqual(len(modules), 8)
        self.assertEqual(
            modules,
            {
                "oidcc-rp-initiated-logout-bad-id-token-hint",
                "oidcc-rp-initiated-logout-bad-post-logout-redirect-uri",
                "oidcc-rp-initiated-logout-modified-id-token-hint",
                "oidcc-rp-initiated-logout-no-id-token-hint",
                "oidcc-rp-initiated-logout-no-params",
                "oidcc-rp-initiated-logout-no-post-logout-redirect-uri",
                "oidcc-rp-initiated-logout-only-state",
                "oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri",
            },
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
                        "endpoint": "https://issuer.example/bc-authorize?code=secret",
                        "body": "<html>token=secret</html>",
                        "response_status_code": 404,
                    },
                }
            ]
        )

        self.assertIn("CallBackchannelAuthenticationEndpoint", context)
        self.assertIn("https://issuer.example/bc-authorize?redacted=1", context)
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

    def test_oidf_log_context_redacts_nested_tokens_headers_and_json_text(self):
        module = load_runner_module()

        context = module.oidf_log_context(
            [
                {
                    "src": "CallTokenEndpointAndReturnFullResponse",
                    "result": "FAILURE",
                    "args": {
                        "response_body": {
                            "access_token": "access-secret",
                            "nested": [{"auth_req_id": "poll-secret"}],
                            "body": '{"refresh_token":"refresh-secret"}',
                        },
                        "backchannel_authentication_endpoint_response_headers": {
                            "Authorization": "Bearer bearer-secret",
                            "Set-Cookie": "sid=cookie-secret; Secure",
                        },
                    },
                }
            ]
        )

        self.assertIn("<redacted>", context)
        for secret in (
            "access-secret",
            "poll-secret",
            "refresh-secret",
            "bearer-secret",
            "cookie-secret",
        ):
            self.assertNotIn(secret, context)

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
