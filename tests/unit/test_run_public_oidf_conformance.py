import importlib.util
import json
import os
import signal
import subprocess
import tempfile
import threading
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


def load_module():
    script = Path(__file__).resolve().parents[2] / "scripts" / "run_public_oidf_conformance.py"
    spec = importlib.util.spec_from_file_location("run_public_oidf_conformance", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class PublicOidfRunnerTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def test_origins_are_normalized_and_non_origin_urls_are_rejected(self):
        self.assertEqual(
            self.module.origin("https://suite.example/", "--suite"),
            "https://suite.example",
        )
        for invalid in ("http://suite.example", "https://suite.example/path", "localhost"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(self.module.PublicRunError):
                    self.module.origin(invalid, "--suite")

    def test_target_metadata_must_match_the_requested_issuer_and_browser_routes(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.geturl.return_value = (
            "https://issuer.example/.well-known/openid-configuration"
        )
        response.read.return_value = json.dumps(
            {
                "issuer": "https://issuer.example",
                "authorization_endpoint": "https://issuer.example/authorize",
                "token_endpoint": "https://issuer.example/token",
                "jwks_uri": "https://issuer.example/jwks",
                "registration_endpoint": "https://issuer.example/register",
                "end_session_endpoint": "https://issuer.example/logout",
                "check_session_iframe": "https://issuer.example/check_session",
                "mtls_endpoint_aliases": {
                    "token_endpoint": "https://issuer.example/token",
                },
            }
        ).encode()
        with mock.patch.object(self.module.urllib.request, "urlopen", return_value=response):
            self.module.verify_target_metadata("https://issuer.example")

        response.read.return_value = json.dumps(
            {
                "issuer": "https://other.example",
                "authorization_endpoint": "https://other.example/authorize",
                "end_session_endpoint": "https://other.example/logout",
                "check_session_iframe": "https://other.example/check_session",
            }
        ).encode()
        with (
            mock.patch.object(self.module.urllib.request, "urlopen", return_value=response),
            self.assertRaisesRegex(self.module.PublicRunError, "issuer does not match"),
        ):
            self.module.verify_target_metadata("https://issuer.example")

        response.read.return_value = json.dumps(
            {
                "issuer": "https://issuer.example",
                "authorization_endpoint": "https://issuer.example/wrong-authorize",
                "end_session_endpoint": "https://issuer.example/logout",
                "check_session_iframe": "https://issuer.example/check_session",
            }
        ).encode()
        with (
            mock.patch.object(self.module.urllib.request, "urlopen", return_value=response),
            self.assertRaisesRegex(
                self.module.PublicRunError, "authorization_endpoint does not match"
            ),
        ):
            self.module.verify_target_metadata("https://issuer.example")

    def test_target_metadata_rejects_cross_origin_protocol_and_mtls_endpoints(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.geturl.return_value = (
            "https://issuer.example/.well-known/openid-configuration"
        )
        base = {
            "issuer": "https://issuer.example",
            "authorization_endpoint": "https://issuer.example/authorize",
            "end_session_endpoint": "https://issuer.example/logout",
            "check_session_iframe": "https://issuer.example/check_session",
        }
        for field, value in (
            ("token_endpoint", "https://other.example/token"),
            (
                "mtls_endpoint_aliases",
                {"token_endpoint": "https://other.example/token"},
            ),
        ):
            with self.subTest(field=field):
                response.read.return_value = json.dumps(
                    {**base, field: value}
                ).encode()
                with (
                    mock.patch.object(
                        self.module.urllib.request, "urlopen", return_value=response
                    ),
                    self.assertRaisesRegex(
                        self.module.PublicRunError, "must remain on --target-issuer"
                    ),
                ):
                    self.module.verify_target_metadata("https://issuer.example")

    def test_cli_defaults_to_the_validated_group_concurrency(self):
        args = self.module.parse_args(
            [
                "--deployed-sha",
                "a" * 40,
                "--target-issuer",
                "https://issuer.example",
                "--conformance-server",
                "https://suite.example",
                "--suite-dir",
                "suite",
                "--suite-revision",
                "b" * 40,
                "--work-dir",
                "work",
                "--export-dir",
                "export",
                "--run-namespace",
                "validated-concurrency",
                "--proxy-trust-bundle",
                "proxy-ca.pem",
                "--proxy-executable",
                "proxy",
                "--nazoauthctl",
                "nazoauthctl",
                "--secret-file",
                "secrets.json",
            ]
        )

        self.assertEqual(args.safe_group_workers, 1)
        self.assertEqual(args.browser_group_workers, 1)
        self.assertEqual(args.lease_ttl_seconds, 28_800)

    def test_secret_input_excludes_per_run_capability_tokens(self):
        self.assertEqual(
            self.module.SECRET_INPUT_FIELDS,
            (
                "oidf_applicant_email",
                "oidf_applicant_password",
                "oidf_admin_email",
                "oidf_admin_password",
                "oidf_admin_totp_secret",
                "oidf_conformance_token",
            ),
        )

    def test_child_environment_strips_secret_shaped_variables(self):
        with mock.patch.dict(
            os.environ,
            {"PATH": "safe", "OIDF_CONFORMANCE_TOKEN": "secret", "DB_PASSWORD": "secret"},
            clear=True,
        ):
            environment = self.module.sanitized_environment()
        self.assertEqual(environment, {"PATH": "safe"})

    def test_private_leased_token_file_is_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.module.private_token_file(root, "t" * 43) as token_file:
                self.assertEqual(token_file.read_text(encoding="utf-8"), "t" * 43)
                if os.name != "nt":
                    self.assertEqual(token_file.stat().st_mode & 0o777, 0o600)
                retained_path = token_file
            self.assertFalse(retained_path.exists())

    def test_onboarding_child_receives_credentials_only_through_stdin(self):
        environment = {
            "OIDF_APPLICANT_EMAIL": "applicant@example.com",
            "OIDF_APPLICANT_PASSWORD": "applicant-password",
            "OIDF_ADMIN_EMAIL": "admin@example.com",
            "OIDF_ADMIN_PASSWORD": "admin-password",
            "OIDF_ADMIN_TOTP_SECRET": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            "OIDF_CONFORMANCE_TOKEN": "suite-token",
        }

        payload = self.module.onboarding_credentials(environment)

        self.assertEqual(
            json.loads(payload),
            {
                "applicant_email": "applicant@example.com",
                "applicant_password": "applicant-password",
                "admin_email": "admin@example.com",
                "admin_password": "admin-password",
                "admin_mfa_totp_secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            },
        )
        arguments = self.module.onboarding_args(
            "apply",
            Path("work"),
            "https://issuer.example",
            "018f8f5f-79b2-7a8a-b3f2-577b1a705a4d",
        )
        self.assertIn("--credentials-stdin", arguments)
        self.assertEqual(
            arguments[arguments.index("--lease-id") + 1],
            "018f8f5f-79b2-7a8a-b3f2-577b1a705a4d",
        )

    def test_suite_runner_config_cleanup_removes_only_generated_untracked_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            suite = root / "suite"
            scripts = suite / "scripts"
            scripts.mkdir(parents=True)
            work = root / "work"
            work.mkdir()
            generated = scripts / "oidf-generated-plan-config.json"
            generated.write_text("secret\n", encoding="utf-8")
            unrelated = scripts / "operator-note.txt"
            unrelated.write_text("keep\n", encoding="utf-8")
            (work / "oidf-plan-configs.json").write_text(
                json.dumps({"configs": {generated.name: {}}}),
                encoding="utf-8",
            )

            with mock.patch.object(self.module, "output", return_value=""):
                self.module.cleanup_suite_runner_configs(suite, work)

            self.assertFalse(generated.exists())
            self.assertTrue(unrelated.exists())

    def test_suite_runner_config_cleanup_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            suite = root / "suite"
            (suite / "scripts").mkdir(parents=True)
            work = root / "work"
            work.mkdir()
            (work / "oidf-plan-configs.json").write_text(
                json.dumps({"configs": {"../oidf-escape-plan-config.json": {}}}),
                encoding="utf-8",
            )

            with (
                mock.patch.object(self.module, "output", return_value=""),
                self.assertRaisesRegex(self.module.PublicRunError, "unsafe OIDF runner config filename"),
            ):
                self.module.cleanup_suite_runner_configs(suite, work)

    def test_failure_path_cleans_configs_from_the_resolved_work_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            suite = root / "suite"
            suite.mkdir()
            work = root / "work"
            export = root / "export"
            args = Namespace(
                target_issuer="https://issuer.example",
                conformance_server="https://suite.example",
                work_dir=work,
                export_dir=export,
                suite_dir=suite,
                deployed_sha="a" * 40,
                suite_revision="b" * 40,
                run_namespace="failure-cleanup",
                proxy_trust_bundle=root / "trust.pem",
                proxy_executable=root / "proxy",
                nazoauthctl=root / "nazoauthctl",
                nazoauthctl_config=None,
                lease_ttl_seconds=28_800,
                secrets_stdin=True,
                secret_fd=None,
                secret_file=None,
                timeout_seconds=100,
                monitor_interval_seconds=5,
                final_stabilization_seconds=45,
            )
            args.nazoauthctl.write_text("binary", encoding="utf-8")

            with (
                mock.patch.object(self.module, "verify_source"),
                mock.patch.object(self.module, "verify_suite"),
                mock.patch.object(self.module, "verify_target_metadata"),
                mock.patch.object(
                    self.module,
                    "read_secret_document",
                    return_value={
                        "oidf_applicant_email": "applicant@example.com",
                        "oidf_applicant_password": "applicant-password",
                        "oidf_admin_email": "admin@example.com",
                        "oidf_admin_password": "admin-password",
                        "oidf_admin_totp_secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
                        "oidf_conformance_token": "token",
                    },
                ),
                mock.patch.object(
                    self.module, "command", side_effect=RuntimeError("prepare failed")
                ),
                mock.patch.object(self.module, "ProxyTrust") as proxy_trust,
                mock.patch.object(
                    self.module, "cleanup_suite_runner_configs"
                ) as cleanup,
                mock.patch.object(self.module, "sanitize_evidence_tree"),
                mock.patch.object(self.module, "protect_directory"),
                self.assertRaisesRegex(RuntimeError, "prepare failed"),
            ):
                self.module.run(args)

            cleanup.assert_called_once_with(suite.resolve(), work.resolve())
            proxy_trust.return_value.restore.assert_called_once_with()

    def test_run_binds_onboarding_to_a_time_bounded_lease_and_retires_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            suite = root / "suite"
            suite.mkdir()
            work = root / "work"
            export = root / "export"
            ctl = root / "nazoauthctl"
            ctl.write_text("binary", encoding="utf-8")
            args = Namespace(
                target_issuer="https://issuer.example",
                conformance_server="https://suite.example",
                work_dir=work,
                export_dir=export,
                suite_dir=suite,
                deployed_sha="a" * 40,
                suite_revision="b" * 40,
                run_namespace="lease-bound-run",
                proxy_trust_bundle=root / "trust.pem",
                proxy_executable=root / "proxy",
                nazoauthctl=ctl,
                nazoauthctl_config=None,
                lease_ttl_seconds=28_800,
                secrets_stdin=True,
                secret_fd=None,
                secret_file=None,
                timeout_seconds=100,
                monitor_interval_seconds=5,
                final_stabilization_seconds=0,
            )
            lease_id = "018f8f5f-79b2-7a8a-b3f2-577b1a705a4d"
            leased_dynamic_registration_tokens = []
            leased_ciba_automated_decision_tokens = []

            def command_side_effect(arguments, **_kwargs):
                if any(str(value).endswith("prepare_oidf_black_box.py") for value in arguments):
                    work.mkdir()
                    (work / "oidf-onboarding-manifest.json").write_text(
                        "{}\n", encoding="utf-8"
                    )
                if (
                    any(
                        str(value).endswith("apply_public_conformance_onboarding.py")
                        for value in arguments
                    )
                    and "apply" in arguments
                ):
                    (work / "oidf-onboarding-state.json").write_text(
                        "{}\n", encoding="utf-8"
                    )

            def create_side_effect(*_args, **kwargs):
                leased_dynamic_registration_tokens.append(
                    kwargs["dynamic_registration_token_file"].read_text(
                        encoding="utf-8"
                    )
                )
                leased_ciba_automated_decision_tokens.append(
                    kwargs["ciba_automated_decision_token_file"].read_text(
                        encoding="utf-8"
                    )
                )
                return lease_id

            with (
                mock.patch.object(self.module, "verify_source"),
                mock.patch.object(self.module, "verify_suite"),
                mock.patch.object(self.module, "verify_target_metadata"),
                mock.patch.object(
                    self.module,
                    "read_secret_document",
                    return_value={
                        "oidf_applicant_email": "applicant@example.com",
                        "oidf_applicant_password": "applicant-password",
                        "oidf_admin_email": "admin@example.com",
                        "oidf_admin_password": "admin-password",
                        "oidf_admin_totp_secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
                        "oidf_conformance_token": "token",
                    },
                ),
                mock.patch.object(
                    self.module, "command", side_effect=command_side_effect
                ) as command,
                mock.patch.object(
                    self.module, "create_lease", side_effect=create_side_effect
                ) as create,
                mock.patch.object(self.module, "revoke_and_cleanup") as revoke,
                mock.patch.object(self.module, "ProxyTrust"),
                mock.patch.object(self.module, "verify_suite_boundary"),
                mock.patch.object(self.module, "run_plan_groups"),
                mock.patch.object(self.module, "inspect_complete_matrix"),
                mock.patch.object(self.module, "cleanup_suite_runner_configs"),
                mock.patch.object(self.module, "sanitize_evidence_tree"),
                mock.patch.object(self.module, "protect_directory"),
            ):
                self.module.run(args)

            create.assert_called_once_with(
                ctl.resolve(),
                None,
                profile="oidc-fapi-ciba",
                material=work.resolve() / "oidf-onboarding-manifest.json",
                dynamic_registration_token_file=mock.ANY,
                ciba_automated_decision_token_file=mock.ANY,
                ttl_seconds=28_800,
                candidate=None,
            )
            self.assertEqual(len(leased_dynamic_registration_tokens), 1)
            self.assertEqual(len(leased_ciba_automated_decision_tokens), 1)
            self.assertGreaterEqual(len(leased_dynamic_registration_tokens[0]), 32)
            self.assertGreaterEqual(len(leased_ciba_automated_decision_tokens[0]), 32)
            self.assertNotEqual(
                leased_dynamic_registration_tokens[0],
                leased_ciba_automated_decision_tokens[0],
            )
            onboarding_calls = [
                call.args[0]
                for call in command.call_args_list
                if any(
                    str(value).endswith("apply_public_conformance_onboarding.py")
                    for value in call.args[0]
                )
                and "apply" in call.args[0]
            ]
            self.assertEqual(len(onboarding_calls), 1)
            self.assertEqual(
                onboarding_calls[0][onboarding_calls[0].index("--lease-id") + 1],
                lease_id,
            )
            revoke.assert_called_once_with(
                ctl.resolve(), None, lease_id, candidate=None
            )

    def test_sigterm_after_lease_creation_runs_all_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            suite = root / "suite"
            suite.mkdir()
            work = root / "work"
            export = root / "export"
            ctl = root / "nazoauthctl"
            ctl.write_text("binary", encoding="utf-8")
            args = Namespace(
                target_issuer="https://issuer.example",
                conformance_server="https://suite.example",
                work_dir=work,
                export_dir=export,
                suite_dir=suite,
                deployed_sha="a" * 40,
                suite_revision="b" * 40,
                run_namespace="terminated-run",
                proxy_trust_bundle=root / "trust.pem",
                proxy_executable=root / "proxy",
                nazoauthctl=ctl,
                nazoauthctl_config=None,
                lease_ttl_seconds=28_800,
                secrets_stdin=True,
                secret_fd=None,
                secret_file=None,
                timeout_seconds=100,
                monitor_interval_seconds=5,
                final_stabilization_seconds=0,
            )
            lease_id = "018f8f5f-79b2-7a8a-b3f2-577b1a705a4d"

            def command_side_effect(arguments, **_kwargs):
                if any(str(value).endswith("prepare_oidf_black_box.py") for value in arguments):
                    work.mkdir()
                    (work / "oidf-onboarding-manifest.json").write_text(
                        "{}\n", encoding="utf-8"
                    )
                if (
                    any(
                        str(value).endswith("apply_public_conformance_onboarding.py")
                        for value in arguments
                    )
                    and "apply" in arguments
                ):
                    (work / "oidf-onboarding-state.json").write_text(
                        "{}\n", encoding="utf-8"
                    )

            def terminate_during_plans(*_args, **_kwargs):
                self.module.request_termination(signal.SIGTERM, None)

            with (
                mock.patch.object(self.module, "verify_source"),
                mock.patch.object(self.module, "verify_suite"),
                mock.patch.object(self.module, "verify_target_metadata"),
                mock.patch.object(
                    self.module,
                    "read_secret_document",
                    return_value={
                        "oidf_applicant_email": "applicant@example.com",
                        "oidf_applicant_password": "applicant-password",
                        "oidf_admin_email": "admin@example.com",
                        "oidf_admin_password": "admin-password",
                        "oidf_admin_totp_secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
                        "oidf_conformance_token": "token",
                    },
                ),
                mock.patch.object(
                    self.module, "command", side_effect=command_side_effect
                ) as command,
                mock.patch.object(
                    self.module, "create_lease", return_value=lease_id
                ),
                mock.patch.object(self.module, "revoke_and_cleanup") as revoke,
                mock.patch.object(self.module, "ProxyTrust") as proxy_trust,
                mock.patch.object(self.module, "verify_suite_boundary"),
                mock.patch.object(
                    self.module,
                    "run_plan_groups",
                    side_effect=terminate_during_plans,
                ),
                mock.patch.object(self.module, "inspect_complete_matrix"),
                mock.patch.object(
                    self.module, "cleanup_suite_runner_configs"
                ) as suite_cleanup,
                mock.patch.object(self.module, "sanitize_evidence_tree"),
                mock.patch.object(self.module, "protect_directory"),
                self.module.termination_signal_handlers(),
                self.assertRaises(self.module.TerminationRequested) as raised,
            ):
                self.module.run(args)

            self.assertEqual(raised.exception.signum, signal.SIGTERM)
            suite_cleanup.assert_called_once_with(suite.resolve(), work.resolve())
            proxy_trust.return_value.restore.assert_called_once_with()
            revoke.assert_called_once_with(
                ctl.resolve(), None, lease_id, candidate=None
            )
            onboarding_cleanup = [
                call.args[0]
                for call in command.call_args_list
                if any(
                    str(value).endswith("apply_public_conformance_onboarding.py")
                    for value in call.args[0]
                )
                and "cleanup" in call.args[0]
            ]
            self.assertEqual(len(onboarding_cleanup), 1)

    def test_main_maps_sigterm_to_exit_code_143(self):
        with (
            mock.patch.object(self.module, "parse_args", return_value=Namespace()),
            mock.patch.object(
                self.module,
                "run",
                side_effect=self.module.TerminationRequested(signal.SIGTERM),
            ),
        ):
            self.assertEqual(self.module.main([]), 143)

    def test_termination_prevents_queued_groups_from_starting(self):
        invocations = (
            ("01-first", ["runner", "first"]),
            ("02-queued", ["runner", "queued"]),
        )

        def terminate_first(*_args, **_kwargs):
            self.module.request_termination(signal.SIGTERM, None)

        with (
            self.module.termination_signal_handlers(),
            mock.patch.object(
                self.module,
                "command",
                side_effect=terminate_first,
            ) as command,
            self.assertRaises(self.module.TerminationRequested),
        ):
            self.module.run_group_phase(
                "safe",
                invocations,
                (Path("suite"),),
                1,
                {},
                "suite-token",
            )

        command.assert_called_once()

    def test_group_failure_prevents_queued_groups_from_starting(self):
        invocations = (
            ("01-first", ["runner", "first"]),
            ("02-queued", ["runner", "queued"]),
        )

        with (
            mock.patch.object(
                self.module,
                "command",
                side_effect=subprocess.CalledProcessError(1, ["runner", "first"]),
            ) as command,
            self.assertRaises(ExceptionGroup) as raised,
        ):
            self.module.run_group_phase(
                "safe",
                invocations,
                (Path("suite"),),
                1,
                {},
                "suite-token",
            )

        command.assert_called_once()
        self.assertIn("OIDF safe group execution failed", str(raised.exception))

    def test_group_failure_cancels_other_running_group(self):
        invocations = (
            ("01-failing", ["runner", "failing"]),
            ("02-running", ["runner", "running"]),
        )
        both_started = threading.Barrier(2)
        running_cancelled = threading.Event()

        def run_command(invocation, *, cancellation_event, **_kwargs):
            both_started.wait(timeout=2)
            if "failing" in invocation:
                raise subprocess.CalledProcessError(1, invocation)
            if cancellation_event.wait(timeout=2):
                running_cancelled.set()
                raise self.module.GroupCancellationRequested()
            self.fail("running group was not cancelled after its peer failed")

        with (
            mock.patch.object(self.module, "command", side_effect=run_command) as command,
            self.assertRaises(ExceptionGroup),
        ):
            self.module.run_group_phase(
                "safe",
                invocations,
                (Path("suite-1"), Path("suite-2")),
                2,
                {},
                "suite-token",
            )

        self.assertEqual(command.call_count, 2)
        self.assertTrue(running_cancelled.is_set())

    def test_plan_groups_use_explicit_inputs_and_isolate_browser_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "work"
            work.mkdir()
            (work / "oidf-expected-skips.json").write_text("[]\n", encoding="utf-8")
            contracts = root / "tests" / "contracts"
            contracts.mkdir(parents=True)
            (contracts / "oidf-official-expected-warnings.json").write_text(
                "[]\n", encoding="utf-8"
            )
            concurrent = [
                "oidcc-basic-certification-test-plan basic.json",
                "oidcc-formpost-basic-certification-test-plan formpost.json",
                "oidcc-3rdparty-init-login-certification-test-plan thirdparty.json",
                "oidcc-config-certification-test-plan config.json",
                "fapi2-message-signing-final-test-plan message.json",
            ]
            for client_auth_type in ("mtls", "private_key_jwt"):
                for sender_constrain in ("dpop", "mtls"):
                    concurrent.append(
                        "fapi2-security-profile-final-test-plan"
                        f"[client_auth_type={client_auth_type}]"
                        f"[sender_constrain={sender_constrain}] security-{client_auth_type}-{sender_constrain}.json"
                    )
            ciba = [
                "fapi-ciba-id1-test-plan"
                f"[client_auth_type={client_auth_type}][ciba_mode={mode}] ciba-{client_auth_type}-{mode}.json"
                for client_auth_type in ("private_key_jwt", "mtls")
                for mode in ("poll", "ping")
            ]
            files = {
                "oidf-plan-set-concurrent.json": concurrent,
                "oidf-plan-set-ciba.json": ciba,
                "oidf-plan-set-rp-initiated.json": ["rp-initiated plan-rp.json"],
                "oidf-plan-set-backchannel.json": ["backchannel plan-back.json"],
                "oidf-plan-set-frontchannel.json": ["frontchannel plan-front.json"],
                "oidf-plan-set-session.json": ["session plan-session.json"],
            }
            for filename, plans in files.items():
                (work / filename).write_text(json.dumps(plans), encoding="utf-8")
            args = Namespace(
                suite_dir=root / "suite",
                suite_revision="suite-commit",
                conformance_server="https://suite.example",
                target_issuer="https://issuer.example",
                export_dir=root / "results",
                timeout_seconds=100,
                monitor_interval_seconds=5,
            )
            with (
                mock.patch.object(self.module, "command") as command,
                mock.patch.object(self.module, "ROOT", root),
            ):
                self.module.run_plan_groups(args, work, {}, "suite-token")

            self.assertEqual(command.call_count, 14)
            invocations = [call.args[0] for call in command.call_args_list]
            by_group = {
                Path(
                    invocation[invocation.index("--plan-set-json-file") + 1]
                ).stem.removeprefix("oidf-plan-set-"): invocation
                for invocation in invocations
            }
            for invocation in by_group.values():
                self.assertIn("--no-parallel", invocation)
            self.assertTrue(all("--no-api-token" not in invocation for invocation in invocations))
            self.assertTrue(
                all(
                    invocation[invocation.index("--suite-revision") + 1] == "suite-commit"
                    for invocation in invocations
                )
            )
            self.assertTrue(
                all("--expected-failures-file" in invocation for invocation in invocations)
            )

    def test_parallel_group_workers_use_isolated_suite_worktrees(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "work"
            work.mkdir()
            args = Namespace(
                suite_dir=root / "suite",
                suite_revision="suite-commit",
                safe_group_workers=2,
                browser_group_workers=2,
            )
            invocations = (
                ("01-safe-a", ["runner", "--suite-dir", "{suite_dir}", "safe-a"]),
                ("02-safe-b", ["runner", "--suite-dir", "{suite_dir}", "safe-b"]),
                ("03a-ciba", ["runner", "--suite-dir", "{suite_dir}", "ciba"]),
                ("08-browser-a", ["runner", "--suite-dir", "{suite_dir}", "browser-a"]),
                ("09-browser-b", ["runner", "--suite-dir", "{suite_dir}", "browser-b"]),
            )
            safe_barrier = threading.Barrier(2)

            def run_command(invocation, **_kwargs):
                if invocation[-1].startswith("safe-"):
                    safe_barrier.wait(timeout=2)

            with (
                mock.patch.object(
                    self.module,
                    "prepare_group_invocations",
                    return_value=invocations,
                ),
                mock.patch.object(self.module, "add_suite_worktree") as add_worktree,
                mock.patch.object(self.module, "remove_suite_worktree") as remove_worktree,
                mock.patch.object(
                    self.module,
                    "command",
                    side_effect=run_command,
                ) as command,
            ):
                self.module.run_plan_groups(args, work, {}, "suite-token")

            worker_one = work / "suite-workers" / "worker-01"
            worker_two = work / "suite-workers" / "worker-02"
            self.assertEqual(
                add_worktree.call_args_list,
                [
                    mock.call(args.suite_dir, worker_one, "suite-commit"),
                    mock.call(args.suite_dir, worker_two, "suite-commit"),
                ],
            )
            self.assertEqual(
                remove_worktree.call_args_list,
                [
                    mock.call(args.suite_dir, worker_two),
                    mock.call(args.suite_dir, worker_one),
                ],
            )
            suite_arguments = {
                Path(call.args[0][call.args[0].index("--suite-dir") + 1])
                for call in command.call_args_list
            }
            self.assertEqual(suite_arguments, {worker_one, worker_two})

    def test_problem_records_are_filtered_to_the_selected_plan_configs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan_set = root / "plans.json"
            source = root / "warnings.json"
            destination = root / "selected.json"
            plan_set.write_text(
                json.dumps(["plan-a config-a.json", "plan-b config-b.json"]),
                encoding="utf-8",
            )
            source.write_text(
                json.dumps(
                    [
                        {"configuration-filename": "config-a.json", "condition": "A"},
                        {"configuration-filename": "config-c.json", "condition": "C"},
                    ]
                ),
                encoding="utf-8",
            )

            self.module.filter_problem_records(source, plan_set, destination)

            self.assertEqual(
                json.loads(destination.read_text(encoding="utf-8")),
                [{"configuration-filename": "config-a.json", "condition": "A"}],
            )

    def test_official_ingress_warnings_are_not_applied_to_the_public_suite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan_set = root / "plans.json"
            source = root / "warnings.json"
            destination = root / "selected.json"
            plan_set.write_text(json.dumps(["plan-a config-a.json"]), encoding="utf-8")
            source.write_text(
                json.dumps(
                    [
                        {"configuration-filename": "config-a.json", "condition": "A"},
                        {
                            "configuration-filename": "config-a.json",
                            "condition": "EnsureIncomingTls13",
                        },
                    ]
                ),
                encoding="utf-8",
            )

            self.module.filter_problem_records(
                source,
                plan_set,
                destination,
                excluded_conditions=self.module.OFFICIAL_INGRESS_ONLY_WARNING_CONDITIONS,
            )

            self.assertEqual(
                json.loads(destination.read_text(encoding="utf-8")),
                [{"configuration-filename": "config-a.json", "condition": "A"}],
            )

    def test_complete_matrix_is_rechecked_after_stabilization_window(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "work"
            contracts = root / "tests" / "contracts"
            work.mkdir()
            contracts.mkdir(parents=True)
            (work / "oidf-plan-configs.json").write_text(
                json.dumps(
                    {
                        "configs": {
                            "a.json": {"alias": "run-a"},
                            "b.json": {"alias": "run-b"},
                        }
                    }
                ),
                encoding="utf-8",
            )
            (work / "oidf-plan-set.json").write_text(
                json.dumps(["plan-a a.json", "plan-b b.json"]), encoding="utf-8"
            )
            (work / "oidf-expected-skips.json").write_text("[]\n", encoding="utf-8")
            (contracts / "oidf-official-expected-warnings.json").write_text(
                "[]\n", encoding="utf-8"
            )
            args = Namespace(
                conformance_server="https://suite.example",
                final_stabilization_seconds=45,
            )

            with (
                mock.patch.object(self.module, "ROOT", root),
                mock.patch.object(self.module, "inspect_oidf_state", return_value=None) as inspect,
                mock.patch.object(self.module.time, "sleep") as sleep,
            ):
                self.module.inspect_complete_matrix(args, work, "token")

            self.assertEqual(inspect.call_count, 2)
            self.assertEqual(inspect.call_args_list[0].args[2], {"run-a", "run-b"})
            self.assertTrue(inspect.call_args_list[0].kwargs["final"])
            sleep.assert_called_once_with(45)

    def test_complete_matrix_rejects_a_late_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "work"
            contracts = root / "tests" / "contracts"
            work.mkdir()
            contracts.mkdir(parents=True)
            (work / "oidf-plan-configs.json").write_text(
                json.dumps({"configs": {"a.json": {"alias": "run-a"}}}),
                encoding="utf-8",
            )
            (work / "oidf-plan-set.json").write_text(
                json.dumps(["plan-a a.json"]), encoding="utf-8"
            )
            (work / "oidf-expected-skips.json").write_text("[]\n", encoding="utf-8")
            (contracts / "oidf-official-expected-warnings.json").write_text(
                "[]\n", encoding="utf-8"
            )
            args = Namespace(
                conformance_server="https://suite.example",
                final_stabilization_seconds=1,
            )

            with (
                mock.patch.object(self.module, "ROOT", root),
                mock.patch.object(
                    self.module,
                    "inspect_oidf_state",
                    side_effect=(None, "module result FAILED"),
                ),
                mock.patch.object(self.module.time, "sleep"),
                self.assertRaisesRegex(
                    self.module.PublicRunError,
                    "stabilized check failed.*FAILED",
                ),
            ):
                self.module.inspect_complete_matrix(args, work, "token")

    def test_proxy_trust_install_and_restore_are_atomic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "proxy" / "trust.pem"
            target.parent.mkdir()
            target.write_text("old\n", encoding="utf-8")
            executable = root / "proxy-bin"
            executable.write_text("", encoding="utf-8")
            approved = root / "approved.pem"
            approved.write_text("new\n", encoding="utf-8")
            work = root / "work"
            work.mkdir()
            trust = self.module.ProxyTrust(target, executable, work)
            replace = self.module.os.replace

            def same_directory_replace(source, destination):
                if Path(source).parent != Path(destination).parent:
                    raise OSError(18, "Invalid cross-device link")
                return replace(source, destination)

            with (
                mock.patch.object(self.module, "command") as command,
                mock.patch.object(self.module.ssl, "SSLContext"),
                mock.patch.object(
                    self.module.os,
                    "replace",
                    side_effect=same_directory_replace,
                ),
            ):
                trust.install(approved)
                self.assertEqual(target.read_text(encoding="utf-8"), "new\n")
                trust.restore()

            self.assertEqual(target.read_text(encoding="utf-8"), "old\n")
            self.assertFalse((work / "proxy-trust-bundle.before.pem").exists())
            self.assertEqual(command.call_count, 4)

    def test_proxy_validation_failure_restores_previous_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "trust.pem"
            target.write_text("old\n", encoding="utf-8")
            executable = root / "proxy-bin"
            executable.write_text("", encoding="utf-8")
            approved = root / "approved.pem"
            approved.write_text("new\n", encoding="utf-8")
            work = root / "work"
            work.mkdir()
            trust = self.module.ProxyTrust(target, executable, work)
            failure = subprocess.CalledProcessError(1, [str(executable), "-t"])

            with (
                mock.patch.object(
                    self.module,
                    "command",
                    side_effect=(failure, None, None),
                ),
                mock.patch.object(self.module.ssl, "SSLContext"),
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    trust.install(approved)

            self.assertEqual(target.read_text(encoding="utf-8"), "old\n")
            self.assertFalse(trust.installed)


if __name__ == "__main__":
    unittest.main()
