import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


def load_module():
    script = Path(__file__).resolve().parents[2] / "scripts" / "conformance_lease_control.py"
    sys.path.insert(0, str(script.parent))
    spec = importlib.util.spec_from_file_location("conformance_lease_control", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ConformanceLeaseControlTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    @mock.patch("subprocess.run")
    def test_create_uses_ctl_receipt_and_returns_nested_uuid(self, run):
        lease_id = "018f8f5f-79b2-7a8a-b3f2-577b1a705a4d"
        run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps({"result": {"lease_id": lease_id}}), stderr=""
        )

        actual = self.module.create(
            Path("/usr/local/bin/nazoauthctl"),
            Path("/etc/nazoauth/update.json"),
            profile="oidc-fapi-ciba",
            material=Path("/run/oidf-onboarding-manifest.json"),
            dynamic_registration_token_file=Path("/run/dcr-token"),
            ciba_automated_decision_token_file=Path("/run/ciba-token"),
            ttl_seconds=28_800,
        )

        self.assertEqual(actual, lease_id)
        command = run.call_args.args[0]
        self.assertEqual(command[:3], [
            str(Path("/usr/local/bin/nazoauthctl")),
            "--config",
            str(Path("/etc/nazoauth/update.json")),
        ])
        self.assertEqual(command[3:6], ["conformance", "lease", "create"])
        self.assertEqual(command[command.index("--profile") + 1], "oidc-fapi-ciba")
        self.assertEqual(
            command[command.index("--dynamic-registration-token-file") + 1],
            str(Path("/run/dcr-token")),
        )
        self.assertEqual(
            command[command.index("--ciba-automated-decision-token-file") + 1],
            str(Path("/run/ciba-token")),
        )
        self.assertIs(run.call_args.kwargs["stdin"], subprocess.DEVNULL)

    @mock.patch("subprocess.run")
    def test_revoke_is_followed_by_physical_cleanup(self, run):
        run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="{}", stderr=""
        )
        lease_id = "018f8f5f-79b2-7a8a-b3f2-577b1a705a4d"

        self.module.revoke_and_cleanup(Path("/ctl"), None, lease_id)

        self.assertEqual(run.call_count, 2)
        self.assertEqual(
            run.call_args_list[0].args[0],
            [
                str(Path("/ctl")),
                "conformance",
                "lease",
                "revoke",
                "--lease-id",
                lease_id,
                "--yes",
            ],
        )
        self.assertEqual(
            run.call_args_list[1].args[0],
            [str(Path("/ctl")), "conformance", "lease", "cleanup", "--yes"],
        )

    @mock.patch("subprocess.run")
    def test_cleanup_runs_even_when_revoke_fails(self, run):
        run.side_effect = [
            subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="secret-bearing diagnostic"
            ),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="{}", stderr=""),
        ]
        lease_id = "018f8f5f-79b2-7a8a-b3f2-577b1a705a4d"

        with self.assertRaises(self.module.ConformanceLeaseControlError):
            self.module.revoke_and_cleanup(Path("/ctl"), None, lease_id)

        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[1].args[0][-2:], ["cleanup", "--yes"])

    @mock.patch("subprocess.run")
    def test_nonzero_ctl_exit_fails_without_parsing_stderr(self, run):
        run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="secret-bearing diagnostic"
        )

        with self.assertRaisesRegex(
            self.module.ConformanceLeaseControlError,
            "nazoauthctl conformance lease create failed",
        ):
            self.module.create(
                Path("/ctl"),
                None,
                profile="oidc-fapi-ciba",
                material=Path("/manifest.json"),
                ttl_seconds=60,
            )

    @mock.patch("subprocess.run")
    def test_candidate_target_is_bound_before_lease_operation(self, run):
        lease_id = "018f8f5f-79b2-7a8a-b3f2-577b1a705a4d"
        run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps({"lease_id": lease_id}), stderr=""
        )
        candidate = self.module.CandidateTarget(
            "v0.1.19",
            "a" * 40,
            "private-pre-release:" + "a" * 40,
            "sha256:" + "b" * 64,
        )

        self.module.create(
            Path("/ctl"),
            None,
            profile="oidc-fapi-ciba",
            material=Path("/manifest.json"),
            ttl_seconds=28_800,
            candidate=candidate,
        )

        command = run.call_args.args[0]
        self.assertEqual(command[1], "conformance")
        self.assertEqual(command[command.index("--candidate-release") + 1], "v0.1.19")
        self.assertEqual(command[command.index("--candidate-oci-digest") + 1], "sha256:" + "b" * 64)
        self.assertEqual(command[-9:-7], ["lease", "create"])


if __name__ == "__main__":
    unittest.main()
