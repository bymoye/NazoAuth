import importlib.util
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


def load_module():
    path = ROOT / "scripts" / "run_official_oidf_full_matrix.py"
    spec = importlib.util.spec_from_file_location("run_official_oidf_full_matrix", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class OfficialOidfFullMatrixTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def args(self, root: Path) -> Namespace:
        return Namespace(
            deployed_sha="a" * 40,
            deployed_source_dir=None,
            runner_sha=None,
            target_issuer="https://issuer.example",
            suite_dir=root / "suite",
            suite_revision="b" * 40,
            work_dir=root / "work",
            export_dir=root / "export",
            run_namespace="local-official",
            proxy_trust_bundle=root / "proxy-ca.pem",
            proxy_executable=root / "proxy",
            prepared_install_dir=root / "prepared",
            request_object_trust_anchor_pem=root / "request-anchor.pem",
            nazoauthctl=root / "nazoauthctl",
            nazoauthctl_config=None,
            candidate_release=None,
            candidate_revision=None,
            candidate_build_id=None,
            candidate_oci_digest=None,
            lease_ttl_seconds=28_800,
            secrets_stdin=True,
            secret_fd=None,
            secret_file=None,
            protocol_timeout_seconds=14_400,
            protocol_monitor_interval_seconds=30,
            protocol_safe_group_workers=2,
            protocol_browser_group_workers=2,
            protocol_groups=None,
            prior_evidence_manifest=None,
            final_stabilization_seconds=45,
            openid4vc_plan_group_size=17,
            openid4vc_timeout_seconds=4_800,
            openid4vc_monitor_interval_seconds=10,
        )

    def secrets(self) -> dict[str, str]:
        return {field: f"secret-{field}" for field in self.module.SECRET_FIELDS}

    def write_manifest(self, export: Path, plan_count: int = 44) -> Path:
        export.mkdir(parents=True, exist_ok=True)
        path = export / "evidence-manifest.json"
        path.write_text(
            json.dumps(
                {
                    "format_version": 1,
                    "summary": {
                        "archive_count": plan_count,
                        "plan_count": plan_count,
                        "module_count": plan_count,
                        "module_results": {"PASSED": plan_count},
                        "condition_results": {"SUCCESS": plan_count},
                    },
                    "archives": [],
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_local_entry_runs_exact_27_then_17_without_github(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.args(root)
            manifest = args.export_dir / "evidence-manifest.json"
            invocations = []

            def run_child(script, arguments, secrets):
                invocations.append((script, arguments, secrets))

            def sanitize(export):
                return self.write_manifest(export)

            with (
                mock.patch.object(
                    self.module, "read_secret_document", return_value=self.secrets()
                ),
                mock.patch.object(self.module, "run_child", side_effect=run_child),
                mock.patch.object(self.module, "create_suite_worktree"),
                mock.patch.object(self.module, "remove_suite_worktree"),
                mock.patch.object(
                    self.module, "sanitize_evidence_tree", side_effect=sanitize
                ),
            ):
                self.module.run(args)

            self.assertEqual(
                {invocation[0] for invocation in invocations},
                {
                    "run_public_oidf_conformance.py",
                    "run_host_local_openid4vc_conformance.py",
                },
            )
            by_script = {invocation[0]: invocation for invocation in invocations}
            for _, arguments, _ in invocations:
                self.assertIn(self.module.OFFICIAL_CONFORMANCE_SERVER, arguments)
                self.assertNotIn("gh", arguments)
                self.assertNotIn("github", " ".join(arguments).lower())
            self.assertEqual(
                set(by_script["run_public_oidf_conformance.py"][2]),
                {
                    "oidf_applicant_email",
                    "oidf_applicant_password",
                    "oidf_admin_email",
                    "oidf_admin_password",
                    "oidf_admin_totp_secret",
                    "oidf_conformance_token",
                },
            )
            self.assertEqual(
                set(by_script["run_host_local_openid4vc_conformance.py"][2]),
                {
                    "applicant_email",
                    "applicant_password",
                    "admin_email",
                    "admin_password",
                    "admin_mfa_totp_secret",
                    "suite_token",
                    "issuer_management_token",
                    "verifier_management_token",
                },
            )
            receipt = json.loads(
                (args.export_dir / "official-full-matrix-receipt.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(receipt["outcome"], "PASSED")
            self.assertEqual(receipt["evidence"]["summary"]["plan_count"], 44)
            self.assertTrue(manifest.exists())

    def test_child_receives_secrets_only_over_standard_input(self):
        with mock.patch.object(self.module.subprocess, "run") as run:
            run.return_value.returncode = 0
            self.module.run_child(
                "runner.py",
                ["--target", "public"],
                {"token": "private-token"},
            )

        invocation = run.call_args
        command = invocation.args[0]
        self.assertIn("--secrets-stdin", command)
        self.assertNotIn("private-token", command)
        self.assertNotIn("private-token", invocation.kwargs["env"].values())
        self.assertEqual(
            json.loads(invocation.kwargs["input"]), {"token": "private-token"}
        )

    def test_namespace_is_rejected_before_secrets_or_output_are_created(self):
        for namespace in ("contains_underscore", "a" * 23):
            with self.subTest(namespace=namespace), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                args = self.args(root)
                args.run_namespace = namespace
                with (
                    mock.patch.object(self.module, "read_secret_document") as read_secrets,
                    self.assertRaisesRegex(
                        self.module.OfficialFullMatrixError,
                        "must produce 1-32 character lowercase child namespaces",
                    ),
                ):
                    self.module.run(args)

                read_secrets.assert_not_called()
                self.assertFalse(args.work_dir.exists())
                self.assertFalse(args.export_dir.exists())

    def test_longest_valid_base_namespace_produces_valid_child_namespaces(self):
        protocol, openid4vc = self.module.child_run_namespaces("a" * 22)
        self.assertEqual(len(protocol), 31)
        self.assertEqual(len(openid4vc), 32)

    def test_success_refuses_incomplete_matrix_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.args(root)
            args.export_dir.mkdir()
            manifest = self.write_manifest(args.export_dir, plan_count=43)
            with self.assertRaisesRegex(
                self.module.OfficialFullMatrixError, "must bind 44 plan IDs"
            ):
                self.module.write_receipt(args, manifest, outcome="PASSED")


if __name__ == "__main__":
    unittest.main()
